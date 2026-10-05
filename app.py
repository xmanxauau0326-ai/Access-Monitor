#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
app.py — Access Monitor バックエンド本体
Flask + Flask-SocketIO + Supabase + MaxMind GeoLite2

役割:
  1. アクセスログ受信API（既存Webアプリの middleware から POST）
  2. GeoIP 変換
  3. 不審アクセスの自動判定（judge）— 送信側の申告には頼らない
  4. Supabase へ保存（31日保持）
  5. 監視対象URLの管理（追加・一覧・削除）
  6. 管理者向け REST API（統計・直近・検知）
  7. Socket.IO による秒単位のプッシュ配信
  8. 管理者ダッシュボード(templates/dashboard.html)の配信
"""
import os
import re
import logging
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

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
app.config["5c2bfc2abee47feea09a24a3cabaa177a87d8c9e1c1a9076bad299ca6c846992"] = os.getenv("SECRET_KEY", "dev-secret")
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
# 不審アクセスの自動判定
#
#   ※ 送信側（middleware）の申告値は使わない。
#     受信したパス・ステータス・User-Agent から、このサーバー自身が判定する。
# ------------------------------------------------------------------
CRITICAL_PATHS = (
    "/.env", "/.git/config", "/config.php", "/backup.sql", "/db.sql",
    "/wp-config.php", "/credentials.json", "/.aws/credentials",
    "/phpmyadmin", "/wp-login.php", "/xmlrpc.php", "/admin/config",
    "/administrator", "/admin",
)
SCAN_SIGNATURES = ("sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster",
                   "hydra", "zgrab", "nuclei", "python-requests", "curl/",
                   "wget/", "go-http-client")


def judge(path, status, ua):
    """(is_suspicious, severity) を返す。severity は high / medium / low / None"""
    p = (path or "").lower()
    u = (ua or "").lower()
    if any(c in p for c in CRITICAL_PATHS):
        return True, "high"
    if any(s in u for s in SCAN_SIGNATURES):
        return True, "medium"
    if status in (401, 403) and any(k in p for k in ("admin", "login", "config")):
        return True, "high"
    if status == 404 and (".php" in p or "wp-" in p):
        return True, "medium"
    if status and status >= 500:
        return True, "low"
    return False, None


# ------------------------------------------------------------------
# 監視対象URLの管理
# ------------------------------------------------------------------
def normalize_url(v):
    """入力文字列 → {'url':..., 'host':...} / 不正なら None"""
    u = (v or "").strip()
    if not u:
        return None
    if not re.match(r"^https?://", u, re.I):
        u = "https://" + u
    try:
        p = urlparse(u)
    except Exception:  # noqa: BLE001
        return None
    if not p.hostname or "." not in p.hostname:
        return None
    return {"url": u, "host": p.hostname.lower()}


def list_targets(hours=24):
    """登録済みの監視対象（直近24時間のヒット数を添えて）"""
    if supabase is None:
        return []
    res = (supabase.table("targets")
           .select("id,url,host,added")
           .order("id")
           .execute())
    rows = res.data or []

    counts = {}
    try:
        rpc = supabase.rpc("target_counts", {"p_hours": hours}).execute()
        for r in (rpc.data or []):
            counts[r.get("host")] = r.get("hits") or 0
    except Exception as exc:  # noqa: BLE001
        logger.warning("target_counts に失敗。0件で表示します: %s", exc)

    for r in rows:
        r["hits"] = counts.get(r.get("host"), 0)
    return rows


def add_target(raw):
    n = normalize_url(raw)
    if not n:
        return None, "URLの形式が正しくありません（例: https://example.com）"
    if supabase is None:
        return None, "Supabase に接続できていません"
    try:
        chk = (supabase.table("targets")
               .select("id").eq("host", n["host"]).execute())
        if chk.data:
            return None, "すでに登録されています: %s" % n["host"]
        supabase.table("targets").insert({
            "url": n["url"],
            "host": n["host"],
            "added": datetime.now(timezone.utc).isoformat(),
        }).execute()
    except Exception as exc:  # noqa: BLE001
        return None, "登録に失敗しました: %s" % exc
    return n, None


def delete_target(host):
    if supabase is None:
        return False
    try:
        supabase.table("targets").delete().eq("host", host).execute()
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error("target 削除失敗 host=%s: %s", host, exc)
        return False


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

    suspicious, severity = judge(payload.get("path"),
                                 payload.get("status_code"),
                                 payload.get("user_agent"))

    site = (payload.get("site") or "").strip() or None
    if not site and payload.get("referer"):
        try:
            site = urlparse(payload["referer"]).hostname or None
        except Exception:  # noqa: BLE001
            site = None

    row = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "ip": ip,
        "path": payload.get("path"),
        "method": payload.get("method"),
        "status_code": payload.get("status_code"),
        "user_agent": payload.get("user_agent"),
        "referer": payload.get("referer"),
        "is_suspicious": suspicious,
        "severity": severity,
        "site": site,
    }
    geo = lookup_geo(ip)
    row.update(geo)

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
    site = (request.args.get("site") or "").strip() or None
    if supabase is None:
        return jsonify({"error": "supabase not configured"}), 503

    # 集計はサーバー側（PostgreSQL）で行う。行数の上限に引っかからない。
    try:
        rpc = supabase.rpc("stats_recent",
                           {"p_site": site or "", "p_hours": hours}).execute()
        data = rpc.data
        if isinstance(data, list):
            data = data[0] if data else {}
        if isinstance(data, dict) and "total" in data:
            return jsonify(data)
    except Exception as exc:  # noqa: BLE001
        logger.warning("stats_recent に失敗。簡易集計に切り替えます: %s", exc)

    # フォールバック：アプリ側で数える
    since = datetime.now(timezone.utc).timestamp() - hours * 3600
    iso = datetime.fromtimestamp(since, tz=timezone.utc).isoformat()
    q = (supabase.table("access_logs")
         .select("country_code,country_name,is_suspicious")
         .gte("ts", iso).limit(20000))
    if site:
        q = q.eq("site", site)
    rows = q.execute().data or []

    by_country, flagged = {}, 0
    for r in rows:
        key = r.get("country_code") or "??"
        entry = by_country.setdefault(key, {
            "country_code": key,
            "country_name": r.get("country_name") or "Unknown",
            "hits": 0, "suspicious": 0})
        entry["hits"] += 1
        if r.get("is_suspicious"):
            flagged += 1
            entry["suspicious"] += 1

    return jsonify({
        "hours": hours,
        "site": site or "",
        "total": len(rows),
        "flagged": flagged,
        "countries": len([k for k in by_country if k != "??"]),
        "by_country": sorted(by_country.values(),
                             key=lambda x: x["hits"], reverse=True),
    })


@app.route("/api/recent", methods=["GET"])
def api_recent():
    require_admin()
    limit = min(int(request.args.get("limit", 50)), 500)
    site = (request.args.get("site") or "").strip() or None
    flagged = request.args.get("flagged") in ("1", "true", "yes")
    if supabase is None:
        return jsonify({"error": "supabase not configured"}), 503

    q = (supabase.table("access_logs")
         .select("*")
         .order("ts", desc=True)
         .limit(limit))
    if site:
        q = q.eq("site", site)
    if flagged:
        q = q.eq("is_suspicious", True)
    return jsonify({"items": q.execute().data or []})


@app.route("/api/targets", methods=["GET"])
def api_targets():
    return jsonify({"targets": list_targets()})


@app.route("/api/targets/add", methods=["POST"])
def api_targets_add():
    require_admin()
    payload = request.get_json(silent=True) or {}
    n, err = add_target(payload.get("url"))
    if err:
        return jsonify({"status": "error", "message": err}), 400
    return jsonify({"status": "ok", "target": n, "targets": list_targets()})


@app.route("/api/targets/delete", methods=["POST"])
def api_targets_delete():
    require_admin()
    payload = request.get_json(silent=True) or {}
    host = (payload.get("host") or "").strip()
    if not host:
        return jsonify({"status": "error", "message": "host がありません"}), 400
    if not delete_target(host):
        return jsonify({"status": "error", "message": "削除できませんでした"}), 500
    return jsonify({"status": "ok", "targets": list_targets()})


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
#    __main__ ブロックを通らない。そのため、ここで起動する。
#    eventlet 環境では socketio.start_background_task を使う。
# ------------------------------------------------------------------
_bg_started = False


def start_background_jobs():
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
