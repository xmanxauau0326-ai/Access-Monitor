# デプロイ前チェックリスト

作成日: 2026-10-02 / 対象: Access Monitor

## A. 事前準備
- [ ] GitHub アカウント作成済み
- [ ] Supabase プロジェクト作成済み
- [ ] Render アカウント作成済み（GitHub連携）
- [ ] MaxMind アカウント作成済み（GeoLite2 ライセンスキー取得）
- [ ] GeoLite2-City.mmdb を `backend/` に配置済み
- [ ] `supabase_schema.sql` を Supabase SQL Editor で実行済み
- [ ] `backend/.env` を作成し全項目を埋めた
- [ ] `.env` が `.gitignore` に入っている

## B. ローカル動作確認
- [ ] `pip install -r requirements.txt` 成功
- [ ] `python app.py` で起動（ポート5000）
- [ ] `/api/health` が 200 を返す
- [ ] アクセスすると Supabase に 1 行入る
- [ ] ダッシュボードの世界地図にマーカーが出る
- [ ] 別タブで開いたまま再アクセス → 秒単位でマーカーが増える
- [ ] `/api/stats?hours=24` が国別集計を返す

## C. Supabase
- [ ] テーブル `access_logs` 作成済み
- [ ] インデックス（`ts`, `country_code`）作成済み
- [ ] 31日保持ポリシー（アプリ側の定期処理が6時間ごとに実行）設定済み
- [ ] RLS 有効化（anon からは読めない）

## D. Render（バックエンド）
- [ ] GitHub リポジトリへ push 済み（このフォルダを backend ルートに）
- [ ] Web Service 作成、Build: `pip install -r requirements.txt`
- [ ] Start: `gunicorn -k eventlet -w 1 --bind 0.0.0.0:$PORT app:app`（`--bind` 必須／Socket.IO のため worker=1）
- [ ] 環境変数 `PYTHON_VERSION=3.11.11` を設定（未設定だと eventlet が動かない）
- [ ] 環境変数を Render に登録（`.env` の全項目）
- [ ] GeoLite2-City.mmdb をリポジトリに含める（サイズ約 60MB。LFS 推奨）
- [ ] デプロイ成功・ログにエラーなし
- [ ] `https://<service>.onrender.com/api/health` が 200

## E. フロントエンド
- [ ] Flask 同梱の `templates/dashboard.html` を使う場合 → 追加作業なし
- [ ] Next.js を Vercel に置く場合 → `NEXT_PUBLIC_API_BASE` を Render URL に設定

## F. 公開前の最終確認
- [ ] `ADMIN_TOKEN` を推測不能な値に変更
- [ ] CORS の `ALLOWED_ORIGINS` を本番ドメインのみに絞る
- [ ] ドメイン取得・DNS 設定（未定のため保留）
- [ ] 既存Webアプリに middleware を組み込み、実アクセスで検証
- [ ] アラート通知先（メール/Slack）を決定

## G. 保留中（元会話時点で未完）
- [ ] フロントエンド（Next.js）完全コード
- [ ] ドメイン確定
- [ ] 既存Webアプリの特定（汎用想定のまま）
