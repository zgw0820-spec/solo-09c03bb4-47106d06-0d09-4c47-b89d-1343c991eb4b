#!/usr/bin/env python3
"""到期告警端到端验证（真实 nginx / 新建 TLS 握手）。

前置：scripts/local_stack.sh up 已运行（本地栈，:8080 / :8443）。
覆盖：
  - 7 天规则：换上一张 4 天后到期的证书 -> 未确认告警；查看页面包含确认按钮
  - 确认：POST 页面表单 -> 告警保持 open 且 acknowledged
  - 换上一张长期证书 -> 旧告警解除；再换回临期证书 -> 新告警未确认（不沿用旧确认）
  - 上传候选、启用待核实不结案（候选上传后告警不变）
  - 探测中断：nginx 停机后采样 -> 观测不明，告警保留；恢复后告警仍在
"""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

WEB = os.environ.get("WEB", "http://127.0.0.1:8080")
WORK = os.environ.get("LOCAL_WORK", "/tmp/certops-local")
TLS_PORT = int(os.environ.get("TLS_PORT", "8443"))
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

passed, failed = [], []


def check(name, cond, extra=""):
    (passed if cond else failed).append(name)
    print(f"{'PASS' if cond else 'FAIL'}  {name} {extra}")


def api(path):
    with urllib.request.urlopen(WEB + path, timeout=15) as r:
        return json.load(r)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_no_redirect = urllib.request.build_opener(NoRedirect)


def post(path, data):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(
        WEB + path, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with _no_redirect.open(req, timeout=30) as r:
            body = r.read()
            try:
                return r.status, json.loads(body)
            except ValueError:
                return r.status, {}
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {}


def upload(out_dir, days):
    subprocess.run(
        [sys.executable, os.path.join(ROOT, "scripts", "make_cert.py"),
         "--data-dir", f"{WORK}/data", "--out-dir", out_dir, "--days", str(days)],
        check=True, capture_output=True,
    )
    boundary = "----alertboundary"
    files = {}
    for k, name in (("cert_file", "chain.pem"), ("key_file", "key.pem")):
        with open(f"{out_dir}/{name}", "rb") as f:
            files[k] = (name, f.read())
    body = b""
    for k, (fname, content) in files.items():
        body += (
            f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"; '
            f'filename="{fname}"\r\nContent-Type: application/x-pem-file\r\n\r\n'
        ).encode() + content + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    req = urllib.request.Request(
        WEB + "/upload", data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)["version_id"]


def current_active():
    return api("/api/status")["active_version_id"]


def activate(vid):
    return post("/activate", {"version_id": vid, "base_version_id": current_active()})


def wait_for(pred, timeout=20, interval=0.5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            value = pred()
        except Exception:
            value = None
        if value:
            return value
        time.sleep(interval)
    return None


def open_alerts():
    return api("/api/alerts")["open"]


def page_html():
    with urllib.request.urlopen(WEB + "/", timeout=15) as r:
        return r.read().decode()


def main():
    base = api("/api/alerts")
    check("告警 API 可访问", "lead_days" in base and base["lead_days"] == 7)
    check("初始服务证书未临期（种子证书 330 天）",
          base["observation"]["served_remaining_days"] > 7)
    check("初始无未结告警", base["open"] == [])

    # 1. 换上一张 4 天后到期的证书 -> 未确认告警
    v_short = upload("/tmp/alert-short", 4)
    code, resp = activate(v_short)
    check("启用 4 天证书成功", resp.get("op", {}).get("state") == "succeeded",
          f"code={code} op={resp.get('op', {}).get('state')}")
    alerts = wait_for(lambda: api("/api/alerts")["open"])
    check("进入提前 7 天窗口生成告警", bool(alerts))
    a1 = alerts[0]
    check("告警指纹 == 实测服务指纹",
          a1["fingerprint"] == api("/api/alerts")["observation"]["served_fingerprint"])
    check("新告警为未确认", a1["acknowledged"] is False)
    check("告警剩余天数 <= 7", a1["remaining_days"] <= 7)
    html = page_html()
    check("页面展示告警与确认按钮",
          f'name="alert_id" value="{a1["id"]}"' in html and "确认本条告警" in html)

    # 2. 上传候选不结案
    v_long = upload("/tmp/alert-long", 365)
    time.sleep(2.5)
    check("仅上传候选不解除告警",
          [x["id"] for x in api("/api/alerts")["open"]] == [a1["id"]])

    # 3. 页面确认
    code, _ = post("/alerts/ack",
                   {"alert_id": a1["id"], "alert_key": a1["alert_key"], "redirect": "1"})
    check("页面确认告警返回成功", code in (200, 303), f"code={code}")
    a1b = api("/api/alerts")["open"][0]
    check("确认后告警仍为 open（不被提前结案）",
          a1b["id"] == a1["id"] and a1b["state"] == "open" and a1b["acknowledged"])
    code, _ = post("/alerts/ack", {"alert_id": a1["id"], "alert_key": "0" * 16})
    check("过期页面确认被拒(409)", code == 409, f"code={code}")

    # 4. 换上长期证书 -> 旧告警解除
    code, resp = activate(v_long)
    check("启用长期证书成功", resp.get("op", {}).get("state") == "succeeded")
    check("换证后旧告警解除",
          wait_for(lambda: api("/api/alerts")["open"] == []) is not None)
    hist = api("/api/alerts")["history"]
    check("历史中保留旧告警且标记已解决",
          any(h["id"] == a1["id"] and h["state"] == "resolved" for h in hist))
    check("旧告警解除原因来自实测换证",
          any("换" in (h["resolve_reason"] or "") for h in hist))

    # 5. 再换回临期证书（新版号）-> 新告警未确认，不沿用旧确认
    v_short2 = upload("/tmp/alert-short2", 5)
    code, resp = activate(v_short2)
    check("启用第二张临期证书成功", resp.get("op", {}).get("state") == "succeeded")
    alerts = wait_for(lambda: api("/api/alerts")["open"])
    a2 = alerts[0]
    check("换上临期证书生成新告警", a2["id"] != a1["id"])
    check("新告警未确认（旧确认不沿用）", a2["acknowledged"] is False)

    # 6. 探测中断：停 nginx -> 观测不明且告警保留
    subprocess.run(["bash", os.path.join(ROOT, "scripts", "local_stack.sh"), "down-nginx"],
                   check=False, capture_output=True)
    time.sleep(1)
    post("/api/alerts/sample", {})
    snap = api("/api/alerts")
    check("探测中断标记观测不明", snap["observation"]["state"] == "unknown",
          snap["observation"]["state"])
    check("探测中断保留告警且不变更确认状态",
          [x["id"] for x in snap["open"]] == [a2["id"]]
          and snap["open"][0]["acknowledged"] is False)
    html = page_html()
    check("页面提示观测不明", "观测不明" in html)

    # 7. 恢复 nginx
    subprocess.run(["bash", os.path.join(ROOT, "scripts", "local_stack.sh"), "start-nginx"],
                   check=True, capture_output=True)
    restored = wait_for(lambda: api("/api/alerts")["observation"]["state"] == "known",
                        timeout=30)
    check("nginx 恢复后观测恢复 known", bool(restored))
    snap = api("/api/alerts")
    check("恢复后告警仍在同一区间",
          [x["id"] for x in snap["open"]] == [a2["id"]]
          and snap["open"][0]["episode_id"] == a2["episode_id"])

    # 8. 确认后重启 web：确认与区间保持
    code, _ = post("/alerts/ack", {"alert_id": a2["id"], "alert_key": a2["alert_key"]})
    check("确认第二条告警", code == 200, f"code={code}")
    subprocess.run(["bash", os.path.join(ROOT, "scripts", "local_stack.sh"), "restart-web"],
                   check=True, capture_output=True)
    snap = wait_for(lambda: api("/api/alerts") if
                    api("/api/alerts")["observation"]["state"] == "known" else None,
                    timeout=30) or api("/api/alerts")
    check("重启后告警仍在且已确认",
          [x["id"] for x in snap["open"]] == [a2["id"]]
          and snap["open"][0]["acknowledged"] is True
          and snap["open"][0]["episode_id"] == a2["episode_id"])

    # 9. 旧证书再次服务：新区间、新告警、不沿用旧确认
    code, resp = activate(v_long)
    check("启用长期证书（离开临期）", resp.get("op", {}).get("state") == "succeeded")
    check("告警解除", wait_for(lambda: api("/api/alerts")["open"] == []) is not None)
    code, resp = activate(v_short)  # 与 a1 相同指纹的旧证书再次服务
    check("旧证书再次启用成功", resp.get("op", {}).get("state") == "succeeded")
    alerts = wait_for(lambda: api("/api/alerts")["open"])
    a3 = alerts[0]
    check("旧证书再次服务生成本次新告警",
          a3["fingerprint"] == a1["fingerprint"] and a3["id"] not in (a1["id"], a2["id"]))
    check("旧确认不被沿用（新告警未确认）", a3["acknowledged"] is False)
    check("新区间不同于首次服务区间", a3["episode_id"] != a1["episode_id"])

    print(f"\n== alerts e2e: {len(passed)} passed, {len(failed)} failed ==")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
