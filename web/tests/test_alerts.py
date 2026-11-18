"""到期告警测试：7 天规则、确认语义、换证/回退/采样交错、探测中断、重启。"""
from __future__ import annotations

import datetime as dt

import pytest

from app import certutil
from app.alerts import LEAD_DAYS, AlertNotFound, AlertStale
from app.service import CertService, Config, ProbeError

DOMAIN = "demo.internal"
UTC = dt.timezone.utc
NOW = dt.datetime(2026, 11, 18, 12, 0, 0, tzinfo=UTC)


class AlertFakeControl:
    """告警测试用控制面：served 可任意指定（含有效期），不依赖 live 文件。"""

    def __init__(self):
        self.served: certutil.ServedCert | None = None
        self.probe_error = False
        self.reload_count = 0
        self.receipt_mode = "ok"

    def probe_cert(self):
        if self.probe_error:
            raise ProbeError("探测中断：connection refused")
        if self.served is None:
            raise ProbeError("尚未提供证书")
        return self.served

    def probe(self):
        return self.probe_cert().fingerprint

    def request_reload(self, token):
        self.reload_count += 1

    def wait_receipt(self, token, timeout):
        return None if self.receipt_mode == "timeout" else "ok"


def served(fp_char: str, not_after: dt.datetime, not_before=None):
    return certutil.ServedCert(
        fingerprint=fp_char * 64,
        not_before=not_before or (not_after - dt.timedelta(days=90)),
        not_after=not_after,
    )


@pytest.fixture()
def cfg(tmp_path):
    return Config(
        site_domain=DOMAIN,
        data_dir=str(tmp_path / "data"),
        live_dir=str(tmp_path / "live"),
        reload_dir=str(tmp_path / "reload"),
        receipt_timeout=0.05,
        verify_timeout=0.2,
        pending_ttl=0.5,
        probe_interval=0.02,
        startup_probe_timeout=0.2,
        restore_interval=100.0,
        alert_interval=3600.0,
    )


@pytest.fixture()
def svc(cfg):
    s = CertService(cfg)
    s.control = AlertFakeControl()
    s.control.served = served(
        "a", NOW + dt.timedelta(days=30), not_before=NOW - dt.timedelta(days=300)
    )
    s.startup(background=False)
    yield s
    s.shutdown()


def sample(svc, now=NOW):
    return svc.sample_alerts(now=now)


def open_alert_ids(svc, now=NOW):
    return [a["id"] for a in svc.alert_snapshot(now=now)["open"]]


# ---------------------------------------------------------------- 7 天规则


def test_expiring_cert_raises_unconfirmed_alert(svc):
    svc.control.served = served("b", NOW + dt.timedelta(days=3))
    sample(svc)
    snap = svc.alert_snapshot(now=NOW)
    assert len(snap["open"]) == 1
    a = snap["open"][0]
    assert a["fingerprint"] == "b" * 64
    assert a["acknowledged"] is False
    assert a["remaining_days"] == 3.0
    assert snap["observation"]["state"] == "known"
    assert snap["observation"]["served_fingerprint"] == "b" * 64


def test_cert_outside_window_has_no_alert(svc):
    sample(svc)
    snap = svc.alert_snapshot(now=NOW)
    assert snap["open"] == []
    assert snap["observation"]["state"] == "known"


def test_window_boundary_is_exactly_seven_days(svc):
    svc.control.served = served("c", NOW + dt.timedelta(days=LEAD_DAYS))
    sample(svc)
    assert len(open_alert_ids(svc)) == 1
    # 7 天零 1 秒：不告警
    svc.control.served = served(
        "d", NOW + dt.timedelta(days=LEAD_DAYS, seconds=1)
    )
    sample(svc)
    assert open_alert_ids(svc) == []


def test_lead_windows_uses_handshake_dates_not_db(svc):
    """有效期来自握手证书本体；DB 中候选版本/版本表不参与判定。"""
    svc.control.served = served("e", NOW + dt.timedelta(days=2))
    sample(svc)
    obs = svc.alert_snapshot(now=NOW)["observation"]
    assert obs["served_not_after"].startswith("2026-11-20")


# ---------------------------------------------------------------- 上传/待核实不结案


def test_upload_candidate_does_not_resolve_alert(svc):
    svc.control.served = served("b", NOW + dt.timedelta(days=2))
    sample(svc)
    # 上传一张长期候选证书（不启用）
    ca_cert = open(f"{svc.cfg.data_dir}/ca/ca.pem", "rb").read()
    ca_key = open(f"{svc.cfg.data_dir}/ca/ca-key.pem", "rb").read()
    chain, key = certutil.generate_server_cert(DOMAIN, ca_cert, ca_key, days_valid=365)
    svc.upload(chain, key)
    sample(svc)
    snap = svc.alert_snapshot(now=NOW)
    assert [a["fingerprint"] for a in snap["open"]] == ["b" * 64]
    assert snap["observation"]["served_fingerprint"] == "b" * 64


def test_pending_activation_does_not_resolve_alert(svc):
    """启用待核实（观测仍是旧证书）时，旧告警仍在且未被确认。"""
    svc.control.served = served("b", NOW + dt.timedelta(days=2))
    sample(svc)
    # 模拟启用：live 文件换了，但 nginx 尚未切（探测仍返回 b）
    ca_cert = open(f"{svc.cfg.data_dir}/ca/ca.pem", "rb").read()
    ca_key = open(f"{svc.cfg.data_dir}/ca/ca-key.pem", "rb").read()
    chain, key = certutil.generate_server_cert(DOMAIN, ca_cert, ca_key, days_valid=365)
    v, _ = svc.upload(chain, key)
    old = svc.control.served
    svc.control.receipt_mode = "timeout"
    svc.control.served = old  # 探测仍拿到旧证书
    op = svc.activate(v["id"], base_version_id=1)
    assert op["state"] == "pending_verify"
    snap = svc.alert_snapshot(now=NOW)
    assert [a["fingerprint"] for a in snap["open"]] == ["b" * 64]
    assert snap["open"][0]["acknowledged"] is False


# ---------------------------------------------------------------- 换证


def test_new_cert_service_resolves_and_replaces_alert(svc):
    old = served("a", NOW + dt.timedelta(days=2))
    svc.control.served = old
    sample(svc)
    aid = open_alert_ids(svc)[0]
    svc.acknowledge_alert(aid, svc.alert_snapshot(now=NOW)["open"][0]["alert_key"], NOW)
    # 换上一张有效期充足的新证书
    svc.control.served = served("f", NOW + dt.timedelta(days=200))
    sample(svc)
    snap = svc.alert_snapshot(now=NOW)
    assert snap["open"] == []
    assert snap["history"][0]["id"] == aid
    assert snap["history"][0]["state"] == "resolved"
    assert "换" in snap["history"][0]["resolve_reason"]


def test_new_expiring_cert_creates_unacknowledged_alert(svc):
    svc.control.served = served("a", NOW + dt.timedelta(days=2))
    sample(svc)
    a1 = svc.alert_snapshot(now=NOW)["open"][0]
    svc.acknowledge_alert(a1["id"], a1["alert_key"], NOW)
    # 换上同样临期的证书（5 天后到期）
    svc.control.served = served("b", NOW + dt.timedelta(days=5))
    sample(svc)
    snap = svc.alert_snapshot(now=NOW)
    assert len(snap["open"]) == 1
    a2 = snap["open"][0]
    assert a2["fingerprint"] == "b" * 64
    assert a2["acknowledged"] is False
    assert a2["id"] != a1["id"]
    assert any(h["id"] == a1["id"] and h["state"] == "resolved" for h in snap["history"])


def test_old_cert_serving_again_does_not_reuse_acknowledgement(svc):
    a_cert = served("a", NOW + dt.timedelta(days=2))
    svc.control.served = a_cert
    sample(svc)
    a1 = svc.alert_snapshot(now=NOW)["open"][0]
    svc.acknowledge_alert(a1["id"], a1["alert_key"], NOW)
    # A -> B（长期）解除；再回退到 A 再次服务
    svc.control.served = served("b", NOW + dt.timedelta(days=200))
    sample(svc)
    assert svc.alert_snapshot(now=NOW)["open"] == []
    svc.control.served = a_cert
    sample(svc)
    snap = svc.alert_snapshot(now=NOW)
    assert len(snap["open"]) == 1
    a2 = snap["open"][0]
    assert a2["fingerprint"] == "a" * 64
    assert a2["episode_id"] != a1["episode_id"]
    assert a2["acknowledged"] is False
    # 旧告警的确认记录仍存在于历史中
    hist = {h["id"]: h for h in snap["history"]}
    assert hist[a1["id"]]["acknowledged"] is True


# ---------------------------------------------------------------- 探测中断


def test_probe_outage_keeps_alert_and_marks_unknown(svc):
    svc.control.served = served("b", NOW + dt.timedelta(days=2))
    sample(svc)
    aid = open_alert_ids(svc)[0]
    svc.control.probe_error = True
    res = sample(svc)
    assert res["state"] == "unknown"
    snap = svc.alert_snapshot(now=NOW)
    assert [a["id"] for a in snap["open"]] == [aid]
    assert snap["open"][0]["acknowledged"] is False
    assert snap["observation"]["state"] == "unknown"
    assert "探测中断" in snap["observation"]["last_error"]
    # 恢复探测后告警仍在（同一区间，不重复生成）
    svc.control.probe_error = False
    sample(svc)
    snap = svc.alert_snapshot(now=NOW)
    assert [a["id"] for a in snap["open"]] == [aid]
    assert snap["observation"]["state"] == "known"


def test_outage_does_not_clear_acknowledgement(svc):
    svc.control.served = served("b", NOW + dt.timedelta(days=2))
    sample(svc)
    a = svc.alert_snapshot(now=NOW)["open"][0]
    svc.acknowledge_alert(a["id"], a["alert_key"], NOW)
    svc.control.probe_error = True
    sample(svc)
    snap = svc.alert_snapshot(now=NOW)
    assert snap["open"][0]["acknowledged"] is True


# ---------------------------------------------------------------- 采样交错


def test_late_old_sample_cannot_clear_new_alert(svc):
    """先登记的旧采样（旧证书，长期）在换证后落库，必须整条作废。"""
    engine = svc.alerts
    svc.control.served = served("a", NOW + dt.timedelta(days=200))
    sample(svc)
    assert svc.alert_snapshot(now=NOW)["open"] == []
    # 旧采样开始：此时观测到的是"长期"证书
    seq, epoch = engine._claim(NOW)
    stale_cert = svc.control.served
    # 期间完成换证：新证书临期并已实际服务
    svc.control.served = served("b", NOW + dt.timedelta(days=2))
    engine.bump_epoch()
    engine.sample_once(NOW)
    assert len(svc.alert_snapshot(now=NOW)["open"]) == 1
    # 迟到的旧采样提交
    res = engine._commit(seq, epoch, stale_cert, None, NOW)
    assert res["stale"] is True
    snap = svc.alert_snapshot(now=NOW)
    assert [a["fingerprint"] for a in snap["open"]] == ["b" * 64]
    assert snap["observation"]["served_fingerprint"] == "b" * 64


def test_late_sample_with_older_seq_discarded(svc):
    """同纪元下，序号更旧的采样迟到也不能覆盖新采样。"""
    engine = svc.alerts
    svc.control.served = served("b", NOW + dt.timedelta(days=2))
    seq, epoch = engine._claim(NOW)
    new_cert = svc.control.served
    engine.sample_once(NOW)  # 更新的采样（序号更大）
    # 旧采样带的是"长期"证书的假象
    res = engine._commit(
        seq, epoch, served("a", NOW + dt.timedelta(days=200)), None, NOW
    )
    assert res["stale"] is True
    snap = svc.alert_snapshot(now=NOW)
    assert [a["fingerprint"] for a in snap["open"]] == ["b" * 64]
    assert snap["observation"]["served_fingerprint"] == "b" * 64


def test_failed_probe_sample_cannot_clear_new_alert(svc):
    """迟到的"探测失败"旧采样不得把新告警改成观测不明或解除它。"""
    engine = svc.alerts
    seq, epoch = engine._claim(NOW)
    svc.control.served = served("b", NOW + dt.timedelta(days=2))
    engine.bump_epoch()
    engine.sample_once(NOW)
    res = engine._commit(seq, epoch, None, "connection refused", NOW)
    assert res["stale"] is True
    snap = svc.alert_snapshot(now=NOW)
    assert snap["observation"]["state"] == "known"
    assert len(snap["open"]) == 1


# ---------------------------------------------------------------- 确认语义


def test_acknowledge_only_affects_current_alert(svc):
    svc.control.served = served("b", NOW + dt.timedelta(days=2))
    sample(svc)
    snap = svc.alert_snapshot(now=NOW)
    a = snap["open"][0]
    with pytest.raises(AlertStale):
        svc.acknowledge_alert(a["id"], "0" * 16, NOW)  # 页面已过期
    with pytest.raises(AlertNotFound):
        svc.acknowledge_alert(9999, a["alert_key"], NOW)
    acked = svc.acknowledge_alert(a["id"], a["alert_key"], NOW)
    assert acked["acknowledged"] is True
    # 确认不解除告警
    snap = svc.alert_snapshot(now=NOW)
    assert snap["open"][0]["id"] == a["id"]
    assert snap["open"][0]["acknowledged"] is True
    # 重复确认幂等
    again = svc.acknowledge_alert(a["id"], a["alert_key"], NOW)
    assert again["acknowledged"] is True
    assert again["acknowledged_at"] == acked["acknowledged_at"]


def test_acknowledge_rejected_after_alert_resolved(svc):
    svc.control.served = served("b", NOW + dt.timedelta(days=2))
    sample(svc)
    a = svc.alert_snapshot(now=NOW)["open"][0]
    svc.control.served = served("c", NOW + dt.timedelta(days=200))
    sample(svc)
    with pytest.raises(AlertStale, match="已结束"):
        svc.acknowledge_alert(a["id"], a["alert_key"], NOW)


# ---------------------------------------------------------------- 重启


def test_restart_preserves_acknowledgement_and_episode(cfg):
    s1 = CertService(cfg)
    s1.control = AlertFakeControl()
    s1.control.served = served("b", NOW + dt.timedelta(days=2))
    s1.startup(background=False)
    a = s1.alert_snapshot()["open"][0]
    s1.acknowledge_alert(a["id"], a["alert_key"])
    s1.shutdown()

    s2 = CertService(cfg)
    s2.control = AlertFakeControl()
    s2.control.served = served("b", NOW + dt.timedelta(days=2))
    s2.startup(background=False)
    snap = s2.alert_snapshot()
    assert [x["id"] for x in snap["open"]] == [a["id"]]
    assert snap["open"][0]["acknowledged"] is True
    assert snap["open"][0]["episode_id"] == a["episode_id"]
    s2.shutdown()

    # 重启后换证：新告警仍是未确认
    s3 = CertService(cfg)
    s3.control = AlertFakeControl()
    s3.control.served = served("c", NOW + dt.timedelta(days=4))
    s3.startup(background=False)
    snap = s3.alert_snapshot()
    assert len(snap["open"]) == 1
    assert snap["open"][0]["acknowledged"] is False
    assert snap["open"][0]["fingerprint"] == "c" * 64
    s3.shutdown()


def test_restart_during_outage_keeps_alert(svc, cfg):
    svc.control.served = served("b", NOW + dt.timedelta(days=2))
    sample(svc)
    aid = open_alert_ids(svc)[0]
    svc.shutdown()

    s2 = CertService(cfg)
    s2.control = AlertFakeControl()
    s2.control.probe_error = True
    s2.startup(background=False)
    snap = s2.alert_snapshot()
    assert [x["id"] for x in snap["open"]] == [aid]
    assert snap["observation"]["state"] == "unknown"
    s2.shutdown()
