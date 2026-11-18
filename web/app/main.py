"""FastAPI 入口：单站点证书启用管理页。"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from urllib.parse import quote

from fastapi import FastAPI, Form, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from . import certutil
from . import alerts as alerts_mod
from .service import BadRequest, CertService, Conflict, Config, NotFound

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
)

cfg = Config.from_env()
service = CertService(cfg)


@asynccontextmanager
async def lifespan(app: FastAPI):
    service.startup()
    yield
    service.shutdown()


app = FastAPI(title="证书启用管理", lifespan=lifespan)
templates = Jinja2Templates(directory=__file__.rsplit("/", 1)[0] + "/templates")


def _respond(request: Request, redirect: int, payload: dict, status_code: int = 200):
    """表单提交走 303 回页面；API 调用（redirect=0）返回 JSON。"""
    if redirect:
        key = "msg" if status_code < 400 else "err"
        target = f"/?{key}={quote(str(payload.get(key, payload)))}"
        return RedirectResponse(target, status_code=303)
    return JSONResponse(payload, status_code=status_code)


@app.get("/")
def index(request: Request, msg: str = "", err: str = ""):
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "st": service.status(),
            "msg": msg,
            "err": err,
        },
    )


@app.get("/api/status")
def api_status():
    return service.status()


@app.get("/api/op/{seq}")
def api_op(seq: int):
    try:
        return service.get_op(seq)
    except NotFound as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)


@app.get("/api/alerts")
def api_alerts():
    """当前告警与观测状态（页面与外部监控共用）。"""
    return service.alert_snapshot()


@app.post("/api/alerts/sample")
def api_alerts_sample(redirect: int = Form(0)):
    """立即对站点新建一次 TLS 握手并刷新告警。"""
    result = service.sample_alerts()
    snap = service.alert_snapshot()
    if redirect:
        target = "/?msg=" + quote("已完成一次实测采样")
        return RedirectResponse(target, status_code=303)
    return JSONResponse({"sample": result, "alerts": snap})


@app.post("/alerts/ack")
def ack_alert(
    request: Request,
    alert_id: int = Form(...),
    alert_key: str = Form(...),
    redirect: int = Form(0),
):
    """确认页面所见的本次告警（只作用于该告警，不解除观测）。"""
    try:
        alert = service.acknowledge_alert(alert_id, alert_key)
    except alerts_mod.AlertStale as exc:
        return _respond(request, redirect, {"err": str(exc)}, 409)
    except alerts_mod.AlertError as exc:
        return _respond(request, redirect, {"err": str(exc)}, 404)
    msg = f"告警 #{alert['id']} 已确认（证书仍将在 {alert['not_after'][:10]} 到期）"
    return _respond(request, redirect, {"msg": msg, "alert": alert})


@app.post("/upload")
async def upload(
    request: Request,
    cert_file: UploadFile,
    key_file: UploadFile,
    redirect: int = Form(0),
):
    chain = await cert_file.read()
    key = await key_file.read()
    try:
        version, created = service.upload(chain, key)
    except certutil.CertError as exc:
        return _respond(request, redirect, {"err": f"证书校验失败：{exc}"}, 400)
    if created:
        msg = f"上传成功，已登记为候选版本 #{version['id']}"
    else:
        msg = f"相同证书已存在（版本 #{version['id']}），未重复登记"
    return _respond(request, redirect, {"msg": msg, "version_id": version["id"]})


@app.post("/activate")
def activate(
    request: Request,
    version_id: int = Form(...),
    base_version_id: int = Form(...),
    redirect: int = Form(0),
):
    try:
        op = service.activate(version_id, base_version_id)
    except Conflict as exc:
        return _respond(request, redirect, {"err": str(exc)}, 409)
    except BadRequest as exc:
        return _respond(request, redirect, {"err": str(exc)}, 400)
    except NotFound as exc:
        return _respond(request, redirect, {"err": str(exc)}, 404)
    state_msg = {
        "succeeded": f"启用成功：版本 #{op['version_id']} 已在用，新 TLS 连接已核实",
        "pending_verify": "已提交，但回执不明/暂无法核实，状态待核实，系统会自动跟进",
        "failed": f"启用失败：{op.get('detail') or ''}",
    }
    msg = state_msg.get(op["state"], f"操作状态：{op['state']}")
    code = 200 if op["state"] == "succeeded" else (202 if op["state"] == "pending_verify" else 500)
    return _respond(
        request, redirect, {"msg": msg, "op": op}, code if not redirect else 200
    )
