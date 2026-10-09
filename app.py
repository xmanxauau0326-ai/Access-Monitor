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

【設計上の重要事項：設定は「使うたび」に読む】
  Render 上で「モジュール読み込み時点では環境変数が空、リクエスト処理時には
  入っている」という事象が実際に確認された。そのため、設定値は import 時に
  定数へ固定せず、必要になった時点で os.environ から読む。
  （os.getenv は辞書参照なので性能上の問題はない）
"""
import os
import re
import uuid
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

# .env があれば読み込む（Render では環境変数が直接入る）
load_dotenv()

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# 設定：毎回 os.environ から読む
# ------------------------------------------------------------------
# ------------------------------------------------------------------
# 環境変数の取得：表記ゆれと「見えない空白」を吸収する
#
#   Render 上で「os.environ には40文字あるのに、.strip() すると空になる」
#   という事象が実際に確認された。ASCII の空白だけを除く str.strip() では
#   全角スペース等が残る／あるいは値が空白のみ、といった状態を確実に扱うため、
#   ・キー名は前後空白除去＋大文字化して照合
#   ・値は Unicode の空白文字を「すべて」除去する
#   という方式にする（URL も鍵も空白を含まないため安全）。
# ------------------------------------------------------------------
# ------------------------------------------------------------------
# Supabase の Project URL 既定値
#
#   Project URL はブラウザに露出する公開情報であり、秘密情報ではない
#   （Supabase の公式クライアントはこの URL をブラウザ側で使う）。
#   環境変数 SUPABASE_URL が未設定・空白のみの場合にこれを使う。
#
#   【重要】Secret key（sb_secret_… / service_role）は絶対にここへ書かない。
#           鍵は環境変数からのみ読む。
# ------------------------------------------------------------------
DEFAULT_SUPABASE_URL = "https://tjrlshkuwsfbvttqrafg.supabase.co"


def _env_map():
    """{正規化したキー名: 生の値} を返す"""
    out = {}
    for k, v in os.environ.items():
        out[k.strip().upper()] = v
    return out


def _env_clean(*names):
    """名前の表記ゆれを吸収して値を取り出し、値中の空白を全て除去して返す"""
    env = _env_map()
    for n in names:
        v = env.get(n.strip().upper())
        if v is None:
            continue
        cleaned = "".join(ch for ch in v if not ch.isspace())
        if cleaned:
            return cleaned
    return ""


def _env_raw_len(name):
    v = _env_map().get(name.strip().upper())
    return len(v) if v else 0


def cfg(name, default=""):
    """環境変数を「その都度」読む。値は文字列。"""
    v = os.getenv(name)
    return default if v is None else v


def get_admin_token():
    """管理者トークン（見えない空白も含めて除去して比較する）"""
    return _env_clean("ADMIN_TOKEN")


def get_retention_days():
    try:
        return int(_env_clean("RETENTION_DAYS") or "31")
    except (TypeError, ValueError):
        return 31


def get_geodb_path():
    return _env_clean("GEOIP_DB_PATH") or "GeoLite2-City.mmdb"


def get_collect_token():
    """収集トークン（middleware / Worker と共有）。
    未設定なら空文字を返し、/api/collect の検証は行わない（後方互換）。"""
    return _env_clean("COLLECT_TOKEN")


def get_collect_max_bytes():
    """/api/collect の本文サイズ上限（バイト）。0 以下なら無制限。"""
    try:
        return int(_env_clean("COLLECT_MAX_BYTES") or "16384")
    except (TypeError, ValueError):
        return 16384


# ------------------------------------------------------------------
# Flask / Socket.IO
# ------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = _env_clean("SECRET_KEY") or "dev-secret"

_origins = _env_clean("ALLOWED_ORIGINS") or "*"
socketio = SocketIO(
    app,
    cors_allowed_origins=("*" if _origins == "*"
                          else [o for o in _origins.split(",") if o]),
    async_mode="eventlet",
)

# 起動時に COLLECT_TOKEN の有無を1回だけ通知（値そのものは出さない）
if not get_collect_token():
    logger.warning("COLLECT_TOKEN 未設定: /api/collect は無認証で受け付けます。"
                   "本番では必ず設定してください。")


# ------------------------------------------------------------------
# Supabase クライアント（遅延生成・使い回し）
# ------------------------------------------------------------------
_supabase = None
_supabase_sig = None
_supabase_error = None          # 初期化に失敗した理由（値を含まない要約）


def get_supabase_error():
    return _supabase_error


def get_supabase():
    """Supabase クライアント。設定が揃った時点で初めて生成する。"""
    global _supabase, _supabase_sig, _supabase_error
    url = _env_clean("SUPABASE_URL") or DEFAULT_SUPABASE_URL
    key = _env_clean("SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_KEY")
    if create_client is None:
        _supabase_error = "supabase パッケージが読み込めません（import 失敗）"
        return None
    if not url:
        _supabase_error = ("SUPABASE_URL が空です "
                           "(os.environ 上の長さ=%d / 空白除去後=%d)"
                           % (_env_raw_len("SUPABASE_URL"), len(url)))
        return None
    if not key:
        _supabase_error = ("SUPABASE_SERVICE_ROLE_KEY が空です "
                           "(os.environ 上の長さ=%d / 空白除去後=%d)"
                           % (_env_raw_len("SUPABASE_SERVICE_ROLE_KEY"), len(key)))
        return None
    sig = (url, key)
    if _supabase is None or _supabase_sig != sig:
        try:
            _supabase = create_client(url, key)
            _supabase_sig = sig
            _supabase_error = None
            logger.info("Supabase クライアント初期化 OK")
        except Exception as exc:  # noqa: BLE001
            # 例外文にURLや鍵が混ざる場合があるため種別のみ記録する
            _supabase_error = "%s: %s" % (type(exc).__name__, str(exc)[:200])
            if "Invalid API key" in str(exc):
                # supabase-py 2.6.0 は新形式 sb_secret_... を JWT とみなせず
                # ここで落ちる。原因が分かるように明示する。
                _supabase_error = (
                    "Invalid API key — supabase==2.6.0 は新形式 sb_secret_ に"
                    "未対応です。requirements.txt の supabase を更新するか、"
                    "Supabase の Legacy service_role キー（eyJ…）を使ってください")
            logger.error("Supabase 初期化失敗: %s", _supabase_error)
            return None
    return _supabase


# ------------------------------------------------------------------
# GeoIP（遅延ロード・スレッドセーフ）
# ------------------------------------------------------------------
_geoip_reader = None
_geoip_path_loaded = None
_geoip_lock = threading.Lock()


def get_geoip_reader():
    global _geoip_reader, _geoip_path_loaded
    if geoip2 is None:
        return None
    path = get_geodb_path()
    if _geoip_reader is not None and _geoip_path_loaded == path:
        return _geoip_reader
    with _geoip_lock:
        if _geoip_reader is None or _geoip_path_loaded != path:
            try:
                _geoip_reader = geoip2.database.Reader(path)
                _geoip_path_loaded = path
                logger.info("GeoIP DB ロード OK: %s", path)
            except Exception as exc:  # noqa: BLE001
                logger.warning("GeoIP DB をロードできません (%s): %s", path, exc)
                return None
    return _geoip_reader


def lookup_geo(ip):
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
    sb = get_supabase()
    if sb is None:
        return []
    try:
        res = (sb.table("targets")
               .select("id,url,host,added")
               .order("id")
               .execute())
        rows = res.data or []
    except Exception as exc:  # noqa: BLE001
        # targets テーブル未作成（移行SQLが未実行）でも落とさない
        logger.warning("targets を読めません。移行SQLを実行してください: %s", exc)
        return []

    counts = {}
    try:
        rpc = sb.rpc("target_counts", {"p_hours": hours}).execute()
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
    sb = get_supabase()
    if sb is None:
        return None, "Supabase に接続できていません（環境変数を確認してください）"
    try:
        chk = sb.table("targets").select("id").eq("host", n["host"]).execute()
        if chk.data:
            return None, "すでに登録されています: %s" % n["host"]
        sb.table("targets").insert({
            "url": n["url"],
            "host": n["host"],
            "added": datetime.now(timezone.utc).isoformat(),
        }).execute()
    except Exception as exc:  # noqa: BLE001
        return None, "登録に失敗しました: %s" % exc
    return n, None


def delete_target(host):
    sb = get_supabase()
    if sb is None:
        return False
    try:
        sb.table("targets").delete().eq("host", host).execute()
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error("target 削除失敗 host=%s: %s", host, exc)
        return False


# ------------------------------------------------------------------
# 認証ヘルパ
# ------------------------------------------------------------------
def require_admin():
    token = (request.headers.get("X-Admin-Token")
             or request.args.get("token")
             or "").strip()
    expected = get_admin_token()
    if not expected or token != expected:
        logger.warning("認証失敗: admin_token_set=%s / 受信トークンの長さ=%d",
                       bool(expected), len(token))
        abort(401)


# ------------------------------------------------------------------
# 1) ログ受信API（middleware から）
# ------------------------------------------------------------------
@app.route("/api/collect", methods=["POST"])
def api_collect():
    # --- 収集トークン検証（部外者による偽ログ投入を塞ぐ） ---
    expected_collect = get_collect_token()
    if expected_collect:
        got = (request.headers.get("X-Collect-Token") or "").strip()
        if got != expected_collect:
            logger.warning("collect 拒否（トークン不一致） remote=%s",
                           request.headers.get("X-Forwarded-For",
                                               request.remote_addr))
            return jsonify({"status": "unauthorized"}), 401

    # --- 本文サイズ上限（巨大payloadによるメモリ圧迫を防ぐ） ---
    limit = get_collect_max_bytes()
    if limit and (request.content_length or 0) > limit:
        logger.warning("collect 拒否（本文が大きすぎます） len=%s limit=%s",
                       request.content_length, limit)
        return jsonify({"status": "payload too large"}), 413

    payload = request.get_json(silent=True) or {}
    ip = (payload.get("ip")
          or request.headers.get("X-Forwarded-For", request.remote_addr))

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
    row.update(lookup_geo(ip))

    sb = get_supabase()
    if sb is not None:
        try:
            sb.table("access_logs").insert(row).execute()
        except Exception as exc:  # noqa: BLE001
            # severity / site 列が無い環境（移行SQL未実行）でも記録は続ける
            logger.error("Supabase insert 失敗: %s", exc)
            try:
                slim = {k: v for k, v in row.items()
                        if k not in ("severity", "site")}
                sb.table("access_logs").insert(slim).execute()
                logger.warning("severity/site を外して記録しました。"
                               "移行SQLの実行をおすすめします。")
            except Exception as exc2:  # noqa: BLE001
                logger.error("再試行も失敗しました: %s", exc2)

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
    sb = get_supabase()
    if sb is None:
        return jsonify({"error": "supabase not configured"}), 503

    # 集計はサーバー側（PostgreSQL）で行う。行数の上限に引っかからない。
    try:
        rpc = sb.rpc("stats_recent",
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
    q = (sb.table("access_logs")
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
    sb = get_supabase()
    if sb is None:
        return jsonify({"error": "supabase not configured"}), 503

    q = (sb.table("access_logs")
         .select("*")
         .order("ts", desc=True)
         .limit(limit))
    if site:
        q = q.eq("site", site)
    if flagged:
        q = q.eq("is_suspicious", True)
    return jsonify({"items": q.execute().data or []})


@app.route("/api/sites", methods=["GET"])
def api_sites():
    """記録(access_logs)に現れた site の一覧。登録漏れのサイトも選べるようにする。"""
    require_admin()
    sb = get_supabase()
    if sb is None:
        return jsonify({"error": "supabase not configured"}), 503
    try:
        res = sb.table("access_logs").select("site").limit(5000).execute()
        sites = sorted({(r.get("site") or "").strip()
                        for r in (res.data or [])} - {""})
    except Exception as exc:  # noqa: BLE001
        logger.warning("site 一覧の取得に失敗: %s", exc)
        return jsonify({"sites": []})
    return jsonify({"sites": sites})


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


# 期待する環境変数の名前（値は絶対に扱わない）
EXPECTED_ENV = ("SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "ADMIN_TOKEN",
                "PYTHON_VERSION", "SECRET_KEY", "FLASK_ENV",
                "RETENTION_DAYS", "ALLOWED_ORIGINS")


def supabase_selftest():
    """Supabase への実接続を1回試す。鍵が有効かの最終判定に使う。"""
    sb = get_supabase()
    if sb is None:
        return {"ok": False, "error": get_supabase_error()}
    try:
        sb.table("access_logs").select("id").limit(1).execute()
        return {"ok": True}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False,
                "error": "%s: %s" % (type(exc).__name__, str(exc)[:200])}


# 鍵の種類を判定する。プレフィックスは「種類の識別子」であり秘密ではない
# （Supabase 公式もプレフィックスの記録は許容している）。
# 秘密部分は絶対に扱わない。
KEY_PREFIXES = (
    ("sb_secret_", "sb_secret（新形式・サーバー用）"),
    ("sb_publishable_", "sb_publishable（新形式・公開用）"),
    ("sbp_", "sbp_（個人アクセストークン。データ用ではない）"),
    ("eyJ", "eyJ…（JWT形式＝レガシー anon / service_role）"),
)


def key_kind(value):
    if not value:
        return "未設定"
    for pre, label in KEY_PREFIXES:
        if value.startswith(pre):
            return label
    return "不明な形式（プレフィックスが既知の4種に一致しません）"


def env_shapes():
    """各変数の「形」だけを報告する。値そのものは絶対に含めない。

    - 空白のみの値：空白は秘密情報ではないので、コードポイントで種類を示す
      （例 U+3000 = 全角スペース、U+0020 = 半角スペース）
    - それ以外：URLらしいか／鍵らしいか、といった真偽値のみ
    """
    import unicodedata  # noqa: F401  (将来の拡張用)
    env = _env_map()
    out = {}
    for k in EXPECTED_ENV:
        v = env.get(k)
        if v is None:
            out[k] = {"state": "missing"}
            continue
        clean = _env_clean(k)
        rec = {
            "raw_len": len(v),
            "clean_len": len(clean),
            "without_ascii_ws_len": len(
                "".join(ch for ch in v if ch not in " \t\r\n")),
        }
        if len(v) > 0 and not clean:
            rec["all_whitespace"] = True
            rec["codepoints"] = sorted({"U+%04X" % ord(ch) for ch in v})
        else:
            rec["all_whitespace"] = False
            if k.endswith("URL"):
                rec["starts_https"] = clean.startswith("https://")
                rec["is_supabase_co"] = clean.endswith(".supabase.co")
            if "KEY" in k:
                rec["key_kind"] = key_kind(clean)
        out[k] = rec
    return out


def env_report():
    """環境変数の「名前」と「空かどうか」だけを返す。値は絶対に含めない。

    Render の Shell は有料プラン限定のため、これで代用する。
    キー名に空白が混ざっている場合も repr() で見えるようにしている。
    """
    found = {}
    for k in os.environ:
        u = k.strip().upper()
        if u in EXPECTED_ENV and k not in EXPECTED_ENV:
            found[repr(k)] = "キー名に余分な空白あり"   # 例: 'ADMIN_TOKEN '
    present = {k: ("空" if not os.environ.get(k) else "OK(len=%d)" % len(os.environ[k]))
               for k in EXPECTED_ENV if k in os.environ}
    missing = [k for k in EXPECTED_ENV if k not in os.environ]
    return {"present": present, "missing": missing, "suspicious_keys": found}


@app.route("/api/selftest", methods=["GET"])
def api_selftest():
    """書き込み権限の実テスト。

    読み取りが「空の結果」で成功しても、書き込みが拒否される鍵がある
    （RLS が有効なテーブル + 権限の低い鍵）。監視ログが保存されるかは
    書き込みを試さないと分からないため、テスト行を1件挿入して即座に削除する。
    """
    require_admin()
    sb = get_supabase()
    if sb is None:
        return jsonify({"ok": False, "stage": "client",
                        "error": get_supabase_error()}), 503
    marker = "self-test-" + uuid.uuid4().hex[:12]
    try:
        sb.table("access_logs").insert({
            "ts": datetime.now(timezone.utc).isoformat(),
            "path": "/__selftest__",
            "method": "GET",
            "status_code": 200,
            "is_suspicious": False,
            "site": marker,
        }).execute()
    except Exception as exc:  # noqa: BLE001
        return jsonify({
            "ok": False, "stage": "insert",
            "error": "%s: %s" % (type(exc).__name__, str(exc)[:300]),
            "hint": "書き込みが拒否されています。鍵が service_role 相当かを確認してください。",
        }), 200

    # 後片付け（テスト行を消す）
    cleanup = "ok"
    try:
        sb.table("access_logs").delete().eq("site", marker).execute()
    except Exception as exc:  # noqa: BLE001
        cleanup = "失敗: %s" % str(exc)[:200]

    return jsonify({"ok": True, "stage": "insert",
                    "message": "挿入に成功しました。監視ログは正常に保存されます。",
                    "cleanup": cleanup})


@app.route("/api/health", methods=["GET"])
def api_health():
    # admin_token_set = サーバーが ADMIN_TOKEN を受け取れているか（値は出さない）
    return jsonify({
        "status": "ok",
        "supabase": get_supabase() is not None,
        "supabase_error": get_supabase_error(),
        "geoip": get_geoip_reader() is not None,
        "admin_token_set": bool(get_admin_token()),
        "admin_token_length": len(get_admin_token()),
        **env_report(),
        "shapes": env_shapes(),
        "supabase_url_source": (
            "env" if _env_clean("SUPABASE_URL") else "default(埋め込み)"),
        "supabase_test": supabase_selftest(),
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
        sb = get_supabase()
        if sb is None:
            continue
        days = get_retention_days()
        try:
            cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
            iso = datetime.fromtimestamp(cutoff, tz=timezone.utc).isoformat()
            sb.table("access_logs").delete().lt("ts", iso).execute()
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
                get_retention_days())


start_background_jobs()


# ------------------------------------------------------------------
if __name__ == "__main__":
    socketio.run(app,
                 host="0.0.0.0",
                 port=int(_env_clean("PORT") or "5000"),
                 debug=_env_clean("FLASK_ENV") == "development",
                 allow_unsafe_werkzeug=True)
