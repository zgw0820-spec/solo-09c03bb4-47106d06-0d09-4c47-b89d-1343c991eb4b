"""证书到期告警引擎。

事实来源只有一个：**新建 TLS 握手实际返回的证书**。
数据库里的候选版本、启用操作状态都不参与告警判定，因此"上传候选""启用待核实"
不可能提前结束告警；只有握手观测到服务端换了证书，旧告警才会解除。

关键机制：
- 固定提前 7 天（LEAD_DAYS）进入告警；换上的证书若也临期，会生成新告警，
  且 acknowledged 恒为 0（旧证书的确认不会被继承）。
- 服务区间（episode）：同一指纹连续服务为一个区间；A→B→A 中的第二个 A
  是新区间、新告警，旧区间的确认不会沿用。
- 采样序号 + 观测纪元（sample_epoch）：采样在开始时就登记序号/纪元，
  提交时若已有更新采样或服务配置已变化，则整条观测作废。
  这使得启用/回退与采样交错时，迟到的旧采样无法清掉新告警。
- 探测失败：只把观测状态标为 unknown 并保留告警，绝不据此解除告警。
"""
from __future__ import annotations

import datetime as dt
import hashlib

from . import certutil

UTC = dt.timezone.utc
LEAD_DAYS = 7
LEAD = dt.timedelta(days=LEAD_DAYS)


def _iso(value: dt.datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds")


def _parse(value: str) -> dt.datetime:
    t = dt.datetime.fromisoformat(value)
    if t.tzinfo is None:
        t = t.replace(tzinfo=UTC)
    return t


def _alert_key(row) -> str:
    """页面所见告警的校验键：绑定区间、指纹与到期时刻。"""
    material = f"{row['episode_id']}:{row['fingerprint']}:{row['not_after']}"
    return hashlib.sha256(material.encode()).hexdigest()[:16]


class AlertError(Exception):
    """告警操作失败（面向操作员）。"""


class AlertNotFound(AlertError):
    pass


class AlertStale(AlertError):
    """页面所见告警已变化/已结束，确认不生效。"""


class AlertEngine:
    def __init__(self, db, control):
        self.db = db
        self.control = control

    # ------------------------------------------------------------ 纪元

    def bump_epoch(self) -> None:
        """服务配置即将变化（写证书/重载/回退）。使在途采样全部作废。"""
        ts = _iso(dt.datetime.now(UTC))
        with self.db.txn() as c:
            c.execute(
                "UPDATE observations SET sample_epoch = sample_epoch + 1,"
                " updated_at=? WHERE id=1",
                (ts,),
            )

    # ------------------------------------------------------------ 采样

    def _claim(self, now: dt.datetime) -> tuple[int, int]:
        """登记一次采样，返回 (采样序号, 开始时的观测纪元)。"""
        ts = _iso(now)
        with self.db.txn() as c:
            row = c.execute("SELECT * FROM observations WHERE id=1").fetchone()
            seq = row["last_sample_seq"] + 1
            epoch = row["sample_epoch"]
            c.execute(
                "UPDATE observations SET last_sample_seq=?, last_attempt_at=?,"
                " updated_at=? WHERE id=1",
                (seq, ts, ts),
            )
        return seq, epoch

    def _commit(
        self,
        seq: int,
        epoch: int,
        cert: certutil.ServedCert | None,
        error: str | None,
        now: dt.datetime,
    ) -> dict:
        """提交观测。若期间已有更新采样或纪元变化，整条观测作废。"""
        ts = _iso(now)
        with self.db.txn() as c:
            obs = c.execute("SELECT * FROM observations WHERE id=1").fetchone()
            if obs["last_sample_seq"] > seq or obs["sample_epoch"] != epoch:
                return {
                    "seq": seq,
                    "stale": True,
                    "state": obs["state"],
                    "reason": "已有更新采样或服务配置已变化，本次观测作废",
                }
            if cert is None:
                # 探测中断：只标观测不明，告警原样保留
                c.execute(
                    "UPDATE observations SET state='unknown', last_error=?,"
                    " last_attempt_at=?, updated_at=? WHERE id=1",
                    (error or "探测失败", ts, ts),
                )
                return {
                    "seq": seq,
                    "stale": False,
                    "state": "unknown",
                    "error": error or "探测失败",
                }
            result = self._apply(c, obs, cert, now, ts)
            return {"seq": seq, "stale": False, **result}

    def _apply(self, c, obs, cert: certutil.ServedCert, now: dt.datetime, ts: str):
        fp = cert.fingerprint
        prev_fp = obs["served_fingerprint"]
        episode = obs["episode_id"]
        changes: list[str] = []

        if episode is None or prev_fp != fp:
            if episode is not None:
                c.execute(
                    "UPDATE alert_episodes SET ended_at=? WHERE id=?",
                    (ts, episode),
                )
                c.execute(
                    "UPDATE alerts SET state='resolved', resolved_at=?, updated_at=?,"
                    " resolve_reason=? WHERE episode_id=? AND state='open'",
                    (
                        ts,
                        ts,
                        f"实测观测到服务证书已换为 {fp[:16]}…，旧证书不再服务",
                        episode,
                    ),
                )
                changes.append("旧告警因新证书实际开始服务而解除")
            cur = c.execute(
                "INSERT INTO alert_episodes (fingerprint, not_before, not_after,"
                " started_at) VALUES (?,?,?,?)",
                (fp, _iso(cert.not_before), _iso(cert.not_after), ts),
            )
            episode = cur.lastrowid
            changes.append(f"开始新的服务区间 #{episode}")

        c.execute(
            "UPDATE observations SET state='known', served_fingerprint=?,"
            " served_not_before=?, served_not_after=?, episode_id=?,"
            " last_ok_at=?, last_error=NULL, updated_at=? WHERE id=1",
            (fp, _iso(cert.not_before), _iso(cert.not_after), episode, ts, ts),
        )

        alert_id = None
        if cert.not_after - now <= LEAD:
            row = c.execute(
                "SELECT * FROM alerts WHERE episode_id=? AND state='open'",
                (episode,),
            ).fetchone()
            if row:
                c.execute(
                    "UPDATE alerts SET last_observed_at=?, updated_at=? WHERE id=?",
                    (ts, ts, row["id"]),
                )
                alert_id = row["id"]
            else:
                cur = c.execute(
                    "INSERT INTO alerts (episode_id, fingerprint, not_before,"
                    " not_after, state, acknowledged, created_at, updated_at,"
                    " last_observed_at)"
                    " VALUES (?,?,?,?, 'open', 0, ?,?,?)",
                    (
                        episode,
                        fp,
                        _iso(cert.not_before),
                        _iso(cert.not_after),
                        ts,
                        ts,
                        ts,
                    ),
                )
                alert_id = cur.lastrowid
                changes.append(
                    f"证书进入提前 {LEAD_DAYS} 天到期窗口，生成未确认告警 #{alert_id}"
                )
        return {
            "state": "known",
            "fingerprint": fp,
            "episode_id": episode,
            "alert_id": alert_id,
            "changes": changes,
        }

    def sample_once(self, now: dt.datetime | None = None) -> dict:
        """执行一次真实握手采样并更新告警状态。"""
        now = now or dt.datetime.now(UTC)
        seq, epoch = self._claim(now)
        cert = None
        error = None
        try:
            cert = self.control.probe_cert()
        except Exception as exc:  # 任何探测失败都只能说明"观测不明"
            error = str(exc) or exc.__class__.__name__
        return self._commit(seq, epoch, cert, error, now)

    # ------------------------------------------------------------ 查询

    @staticmethod
    def _remaining_days(not_after: str, now: dt.datetime) -> float:
        return (_parse(not_after) - now).total_seconds() / 86400.0

    def _alert_view(self, row, now: dt.datetime) -> dict:
        days = self._remaining_days(row["not_after"], now)
        return {
            "id": row["id"],
            "episode_id": row["episode_id"],
            "fingerprint": row["fingerprint"],
            "not_before": row["not_before"],
            "not_after": row["not_after"],
            "state": row["state"],
            "acknowledged": bool(row["acknowledged"]),
            "acknowledged_at": row["acknowledged_at"],
            "created_at": row["created_at"],
            "last_observed_at": row["last_observed_at"],
            "resolved_at": row["resolved_at"],
            "resolve_reason": row["resolve_reason"],
            "remaining_days": round(days, 1),
            "expired": days <= 0,
            "alert_key": _alert_key(row),
        }

    def snapshot(self, now: dt.datetime | None = None) -> dict:
        now = now or dt.datetime.now(UTC)
        with self.db.txn() as c:
            obs = c.execute("SELECT * FROM observations WHERE id=1").fetchone()
            open_rows = c.execute(
                "SELECT * FROM alerts WHERE state='open' ORDER BY id DESC"
            ).fetchall()
            history_rows = c.execute(
                "SELECT * FROM alerts WHERE state='resolved'"
                " ORDER BY id DESC LIMIT 8"
            ).fetchall()
        open_alerts = [self._alert_view(r, now) for r in open_rows]
        history = [self._alert_view(r, now) for r in history_rows]
        served_days = (
            self._remaining_days(obs["served_not_after"], now)
            if obs["served_not_after"]
            else None
        )
        return {
            "lead_days": LEAD_DAYS,
            "observation": {
                "state": obs["state"],
                "served_fingerprint": obs["served_fingerprint"],
                "served_not_before": obs["served_not_before"],
                "served_not_after": obs["served_not_after"],
                "served_remaining_days": (
                    round(served_days, 1) if served_days is not None else None
                ),
                "episode_id": obs["episode_id"],
                "last_ok_at": obs["last_ok_at"],
                "last_attempt_at": obs["last_attempt_at"],
                "last_error": obs["last_error"],
                "updated_at": obs["updated_at"],
            },
            "open": open_alerts,
            "history": history,
            "acknowledged_open": [
                a for a in open_alerts if a["acknowledged"]
            ],
        }

    # ------------------------------------------------------------ 确认

    def acknowledge(
        self, alert_id: int, alert_key: str, now: dt.datetime | None = None
    ) -> dict:
        """确认页面所见的这一次告警，只影响该告警本身。"""
        now = now or dt.datetime.now(UTC)
        ts = _iso(now)
        with self.db.txn() as c:
            row = c.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
            if not row:
                raise AlertNotFound(f"告警 #{alert_id} 不存在")
            if alert_key != _alert_key(row):
                raise AlertStale("页面所见的告警已变化，确认未生效，请刷新后重试")
            if row["state"] != "open":
                raise AlertStale(
                    f"告警 #{alert_id} 已结束（{row['resolve_reason'] or '证书已更换'}），"
                    "本次确认未生效"
                )
            if row["acknowledged"]:
                return self._alert_view(row, now)
            c.execute(
                "UPDATE alerts SET acknowledged=1, acknowledged_at=?, updated_at=?"
                " WHERE id=? AND state='open' AND acknowledged=0",
                (ts, ts, alert_id),
            )
            row = c.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
            return self._alert_view(row, now)
