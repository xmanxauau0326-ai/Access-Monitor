#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
middleware.py — 既存の Web アプリ（Flask / Django）に組み込むアクセス収集ミドルウェア

使い方（Flask）:
    from middleware import init_app
    init_app(app, backend_url="https://<render>.onrender.com",
              collect_token="<任意の共有トークン>")

使い方（Django）:
    settings.MIDDLEWARE に "middleware.AccessMonitorMiddleware" を追加し、
    settings に ACCESS_MONITOR_BACKEND / ACCESS_MONITOR_TOKEN を定義する。

設計方針:
  - リクエスト処理をブロックしない（バックグラウンドスレッドで送信）
  - 失敗しても本体アプリに影響を与えない（例外は全て握りつぶしてログのみ）
  - 送信するのは IP / パス / メソッド / ステータス / UA / Referer と時刻のみ
"""
import os
import json
import logging
import threading
import queue
from datetime import datetime, timezone

import urllib.request

logger = logging.getLogger(__name__)

BACKEND_URL = os.getenv("ACCESS_MONITOR_BACKEND", "http://localhost:5000")
COLLECT_TOKEN = os.getenv("ACCESS_MONITOR_TOKEN", "")

_queue: "queue.Queue[dict]" = queue.Queue(maxsize=10000)
_started = False
_lock = threading.Lock()


def _sender_loop():
    """キューに溜まったアクセスを順次送信する常駐スレッド"""
    while True:
        row = _queue.get()
        try:
            data = json.dumps(row).encode("utf-8")
            req = urllib.request.Request(
                f"{BACKEND_URL}/api/collect",
                data=data,
                headers={"Content-Type": "application/json",
                         "X-Collect-Token": COLLECT_TOKEN},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=3).read()
        except Exception as exc:  # noqa: BLE001
            logger.debug("collect 送信失敗（本体には影響なし）: %s", exc)
        finally:
            _queue.task_done()


def _ensure_sender():
    global _started
    if _started:
        return
    with _lock:
        if not _started:
            threading.Thread(target=_sender_loop, daemon=True).start()
            _started = True


def _client_ip(request) -> str:
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or ""


def record(request, status_code=None):
    """1アクセスを記録（非同期・ノンブロッキング）"""
    _ensure_sender()
    try:
        row = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "ip": _client_ip(request),
            "path": request.path,
            "method": request.method,
            "status_code": status_code,
            "user_agent": request.headers.get("User-Agent", "")[:512],
            "referer": request.headers.get("Referer", "")[:512],
        }
        _queue.put_nowait(row)
    except queue.Full:
        logger.warning("collect キューが満杯。1件破棄しました。")
    except Exception as exc:  # noqa: BLE001
        logger.debug("record 失敗: %s", exc)


def init_app(app, backend_url=None, collect_token=None):
    """Flask アプリに組み込む"""
    global BACKEND_URL, COLLECT_TOKEN
    if backend_url:
        BACKEND_URL = backend_url
    if collect_token:
        COLLECT_TOKEN = collect_token

    @app.after_request
    def _after(response):  # noqa: ANN001
        record(request=response.request if hasattr(response, "request") else None_guard(),
               status_code=response.status_code)
        return response

    return app


# --- Flask 用の実装（request コンテキストを使う版） ---
try:
    from flask import request as _flask_request

    def init_app(app, backend_url=None, collect_token=None):  # noqa: F811
        global BACKEND_URL, COLLECT_TOKEN
        if backend_url:
            BACKEND_URL = backend_url
        if collect_token:
            COLLECT_TOKEN = collect_token

        @app.after_request
        def _after(response):  # noqa: ANN001
            try:
                record(_flask_request, status_code=response.status_code)
            except Exception:  # noqa: BLE001
                pass
            return response

        return app

except ImportError:  # Flask が無い環境（Django など）では下の実装を使う
    pass


# --- Django 用 ---
try:
    from django.utils.deprecation import MiddlewareMixin

    class AccessMonitorMiddleware(MiddlewareMixin):  # noqa: D101
        def process_response(self, request, response):  # noqa: ANN001
            try:
                record(request, status_code=getattr(response, "status_code", None))
            except Exception:  # noqa: BLE001
                pass
            return response

except ImportError:
    pass
