#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
app.py — Access Monitor バックエンド本体
Flask + Flask-SocketIO + Supabase + MaxMind GeoLite2

役割:
  1. アクセスログ受信API（既存Webアプリの middleware から POST）
  2. GeoIP 変換
  3. Supabase へ保存（31日保持）
  4. 管理者向け REST API（統計・直近）
  5. Socket.IO による秒単位のプッシュ配信
  6. 管理者ダッシュボード(templates/dashboard.html)の配信
"""
import os
import logging
import threading
import time
from datetime import datetime, timezone

from flask import Flask, request, jsonify, render_template, abort
from flask_socketio import SocketIO, emit
from dotenv import load_dotenv

try:
    import geoip2.database
    import geoip2.errors
except ImportError:  # geoip2 未インストールでも起動はさせる
    geoip2 = None

try:
    from supabase import create_client
except ImportError:
    create_client = None

load_dotenv()

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# 設定
# ------------------------------------------------------------------
SUPABASE_URL = os.getenv("https://tjrlshkuwsfbvttqrafg.supabase.co", "")
SUPABASE_KEY = os.getenv("sb_secret_ItGVE13xAzc-IZu_ZKd6lQ_mqOJYkwx") or os.getenv("SUPABASE_KEY", "")
ADMIN_TOKEN = os.getenv("8XKqhdkatyVNEDX1cUSTvViwosv9peqGt9n31o1t", "")
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "31"))
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "GeoLite2-City.mmdb")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("5c2bfc2abee47feea09a24a3cabaa177a87d8c9e1c1a9076bad299ca6c846992", "dev-secret")
socketio = SocketIO(
    app,
    cors_allowed_origins=ALLOWED_ORIGINS.split(",") if ALLOWED_ORIGINS != "*" else "*",
    async_mode="eventlet",
)

# ------------------------------------------------------------------
# クライアント初期化
# ------------------------------------------------------------------
supabase = None
if create_client and SUPABASE_URL and SUPABASE_KEY:
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        logger.info("Supabase クライアント初期化 OK")
    except Exception as exc:  # noqa: BLE001
        logger.error("Supabase 初期化失敗: %s", exc)

_geoip_reader = None
_geoip_lock = threading.Lock()


def get_geoip_reader():
    """GeoLite2 リーダーを遅延ロード（スレッドセーフ）"""
    global _geoip_reader
    if geoip2 is None:
        return None
    if _geoip_reader is None:
        with _geoip_lock:
            if _geoip_reader is None:
                try:
                    _geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
                    logger.info("GeoIP DB ロード OK: %s", GEOIP_DB_PATH)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("GeoIP DB をロードできません (%s): %s",
                                   GEOIP_DB_PATH, exc)
                    return None
    return _geoip_reader


def lookup_geo(ip: str) -> dict:
    """IP → 国・都市・座標"""
    reader = get_geoip_reader()
    result = {"country_code": None, "country_name": None,
              "city": None, "latitude": None, "longitude": None}
    if reader is None or not ip:
        return result
    try:
        resp = reader.city(ip)
        result.update({
            "country_code": (resp.country.iso_code or None),
            "country_name": (resp.country.name or None),
            "city": (resp.city.name or None),
            "latitude": resp.location.latitude,
            "longitude": resp.location.longitude,
        })
    except geoip2.errors.AddressNotFoundError:
        pass
    except Exception as exc:  # noqa: BLE001
        logger.warning("GeoIP 変換失敗 ip=%s: %s", ip, exc)
    return result


# ------------------------------------------------------------------
# 認証ヘルパ
# ------------------------------------------------------------------
def require_admin():
    token = request.headers.get("X-Admin-Token") or request.args.get("token")
    if not ADMIN_TOKEN or token != ADMIN_TOKEN:
        abort(401)


# ------------------------------------------------------------------
# 1) ログ受信API（middleware から）
# ------------------------------------------------------------------
@app.route("/api/collect", methods=["POST"])
def api_collect():
    payload = request.get_json(silent=True) or {}
    ip = payload.get("ip") or request.headers.get("X-Forwarded-For", request.remote_addr)

    row = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "ip": ip,
        "path": payload.get("path"),
        "method": payload.get("method"),
        "status_code": payload.get("status_code"),
        "user_agent": payload.get("user_agent"),
        "referer": payload.get("referer"),
    }
    geo = lookup_geo(ip)
    row.update(geo)

    # 情報漏洩の観点での簡易フラグ（拡張ポイント）
    row["is_suspicious"] = bool(payload.get("is_suspicious", False))

    if supabase is not None:
        try:
            supabase.table("access_logs").insert(row).execute()
        except Exception as exc:  # noqa: BLE001
            logger.error("Supabase insert 失敗: %s", exc)

    # ダッシュボードへ秒単位で配信
    socketio.emit("new_access", row)
    return jsonify({"status": "ok"}), 202


# ------------------------------------------------------------------
# 2) 管理者向け REST API
# ------------------------------------------------------------------
@app.route("/api/stats", methods=["GET"])
def api_stats():
    require_admin()
    hours = int(request.args.get("hours", 24))
    if supabase is None:
        return jsonify({"error": "supabase not configured"}), 503

    since = datetime.now(timezone.utc).timestamp() - hours * 3600
    iso = datetime.fromtimestamp(since, tz=timezone.utc).isoformat()
    res = (supabase.table("access_logs")
           .select("country_code,country_name,ts")
           .gte("ts", iso)
           .execute())

    rows = res.data or []
    by_country = {}
    for r in rows:
        key = r.get("country_code") or "??"
        entry = by_country.setdefault(key, {
            "country_code": key,
            "country_name": r.get("country_name") or "Unknown",
            "hits": 0})
        entry["hits"] += 1

    return jsonify({
        "hours": hours,
        "total": len(rows),
        "by_country": sorted(by_country.values(),
                             key=lambda x: x["hits"], reverse=True),
    })


@app.route("/api/recent", methods=["GET"])
def api_recent():
    require_admin()
    limit = min(int(request.args.get("limit", 50)), 500)
    if supabase is None:
        return jsonify({"error": "supabase not configured"}), 503

    res = (supabase.table("access_logs")
           .select("*")
           .order("ts", desc=True)
           .limit(limit)
           .execute())
    return jsonify({"items": res.data or []})


@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({
        "status": "ok",
        "supabase": supabase is not None,
        "geoip": get_geoip_reader() is not None,
    })


# ------------------------------------------------------------------
# 3) ダッシュボード
# ------------------------------------------------------------------
@app.route("/")
def dashboard():
    return render_template("dashboard.html")


# ------------------------------------------------------------------
# 4) Socket.IO
# ------------------------------------------------------------------
@socketio.on("connect")
def on_connect():
    logger.info("dashboard connected")
    emit("connected", {"status": "ok"})


# ------------------------------------------------------------------
# 5) 保持期間のクリーンアップ（pg_cron が使えない場合の保険）
# ------------------------------------------------------------------
def cleanup_loop():
    while True:
        time.sleep(6 * 3600)
        if supabase is None:
            continue
        try:
            cutoff = (datetime.now(timezone.utc).timestamp()
                      - RETENTION_DAYS * 86400)
            iso = datetime.fromtimestamp(cutoff, tz=timezone.utc).isoformat()
            supabase.table("access_logs").delete().lt("ts", iso).execute()
            logger.info("古いログを削除しました (< %s)", iso)
        except Exception as exc:  # noqa: BLE001
            logger.warning("クリーンアップ失敗: %s", exc)


# ------------------------------------------------------------------
# 6) バックグラウンド処理の起動
#
#    【重要】gunicorn から読み込まれると __name__ は "app" になり、
#    __main__ ブロックを通らない。以前はそこでスレッドを起動していたため、
#    Render 上ではクリーニング処理が一度も動かなかった（31日保持が効かない）。
#    モジュール読み込み時に1回だけ起動する形に修正。
#    eventlet 環境では socketio.start_background_task を使う。
# ------------------------------------------------------------------
_bg_started = False


def start_background_jobs():
    """保持期間クリーンアップを一度だけ起動する"""
    global _bg_started
    if _bg_started:
        return
    _bg_started = True
    socketio.start_background_task(cleanup_loop)
    logger.info("保持期間クリーンアップを開始しました（%s日保持 / 6時間ごと）",
                RETENTION_DAYS)


start_background_jobs()


# ------------------------------------------------------------------
if __name__ == "__main__":
    socketio.run(app,
                 host="0.0.0.0",
                 port=int(os.getenv("PORT", "5000")),
                 debug=os.getenv("FLASK_ENV") == "development",
                 allow_unsafe_werkzeug=True)
