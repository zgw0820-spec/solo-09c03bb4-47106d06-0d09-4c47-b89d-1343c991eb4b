"""SQLite 存储层：版本表、单例行状态表、操作流水表、到期告警表。

所有写操作通过 DB.txn()（BEGIN IMMEDIATE）串行化，
比较-交换条件（如 base_version、current_op_seq）与修改在同一事务内完成。
告警表只由 AlertEngine 写入，事实来源是新建 TLS 握手实际返回的证书。
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS versions (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  fingerprint   TEXT NOT NULL UNIQUE,
  domain        TEXT NOT NULL,
  subject       TEXT NOT NULL,
  san           TEXT NOT NULL,
  not_before    TEXT NOT NULL,
  not_after     TEXT NOT NULL,
  cert_pem      TEXT NOT NULL,
  key_pem       TEXT NOT NULL,
  status        TEXT NOT NULL,          -- candidate|active|superseded|failed
  created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS state (
  id                INTEGER PRIMARY KEY CHECK (id = 1),
  active_version_id INTEGER,
  current_op_seq    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ops (
  seq              INTEGER PRIMARY KEY,
  version_id       INTEGER NOT NULL,    -- 目标版本
  base_version_id  INTEGER NOT NULL,    -- 提交时页面所见的在用版本
  state            TEXT NOT NULL,       -- activating|pending_verify|succeeded|failed|superseded
  detail           TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

-- 到期告警的观测状态（单例）。只记录"新建 TLS 握手实际看到"的证书，
-- 与数据库里的在用版本无关，因此上传/待核实不会影响告警。
CREATE TABLE IF NOT EXISTS observations (
  id                 INTEGER PRIMARY KEY CHECK (id = 1),
  last_sample_seq    INTEGER NOT NULL DEFAULT 0,  -- 采样序号，防止迟到旧采样覆盖新状态
  sample_epoch       INTEGER NOT NULL DEFAULT 0,  -- 服务配置变化次数，使在途采样作废
  state              TEXT NOT NULL DEFAULT 'unknown',  -- known|unknown（探测是否正常）
  served_fingerprint TEXT,                -- 最近一次成功观测到的证书指纹
  served_not_before  TEXT,
  served_not_after   TEXT,                -- 有效期止（来自握手证书本体）
  episode_id         INTEGER,             -- 当前"连续服务"的区间编号
  last_ok_at         TEXT,
  last_attempt_at    TEXT,
  last_error         TEXT,
  updated_at         TEXT
);

-- 服务区间：每次实际服务的证书发生变化（A->B，或 A->B->A）都开启新区间。
-- 告警确认只属于某个区间里的一次告警，旧区间再次服务不会沿用旧确认。
CREATE TABLE IF NOT EXISTS alert_episodes (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  fingerprint  TEXT NOT NULL,
  not_before   TEXT,
  not_after    TEXT NOT NULL,
  started_at   TEXT NOT NULL,
  ended_at     TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  episode_id      INTEGER NOT NULL,
  fingerprint     TEXT NOT NULL,
  not_before      TEXT,
  not_after       TEXT NOT NULL,
  state           TEXT NOT NULL,          -- open|resolved
  acknowledged    INTEGER NOT NULL DEFAULT 0,
  acknowledged_at TEXT,
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL,
  last_observed_at TEXT,
  resolved_at     TEXT,
  resolve_reason  TEXT
);
"""


class DB:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.execute("PRAGMA foreign_keys=ON")

    def init_schema(self) -> None:
        with self._lock:
            self.conn.executescript(SCHEMA)
            self.conn.execute(
                "INSERT OR IGNORE INTO state (id, active_version_id, current_op_seq)"
                " VALUES (1, NULL, 0)"
            )
            self.conn.execute(
                "INSERT OR IGNORE INTO observations"
                " (id, last_sample_seq, sample_epoch, state, updated_at)"
                " VALUES (1, 0, 0, 'unknown', '')"
            )

    @contextmanager
    def txn(self):
        """串行化的 IMMEDIATE 事务；读多行状态也用它保证一致性。"""
        with self._lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield self.conn
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            else:
                self.conn.execute("COMMIT")

    def close(self) -> None:
        with self._lock:
            self.conn.close()
