-- ============================================================
-- Access Monitor : Supabase スキーマ
-- 版: v2  (2026-10-05 修正)
-- 作成: AI秘書 綾瀬玲奈
--
-- v1 からの修正点
--   1) create extension pg_cron; を削除
--      → SQL Editor から実行すると権限エラーになる。拡張の有効化は
--        Dashboard（Database > Extensions）から行う。
--   2) select cron.schedule(...) を削除
--      → pg_cron が未設定だとここでスクリプト全体が止まるため。
--        31日より古いログの削除はアプリ側の定期処理（6時間ごと）が行う。
--        DB側でも自動削除したい場合のみ、末尾の BLOCK 2 を別途実行する。
--   3) access_logs に site 列を追加
--      → 監視対象URLごとの集計用（複数サイトを1つのDBで管理するため）
--
-- 使い方
--   BLOCK 1 を丸ごと SQL Editor に貼り付けて Run  → これだけで完了
--   BLOCK 3 で結果を確認
--   BLOCK 2 は任意
--
-- すべて if not exists / create or replace で書いてあるため、
-- 途中まで実行済みでも、そのまま再実行して問題ありません。
-- ============================================================


-- ============================================================
-- BLOCK 1 : ここから（これを貼り付けて Run）
-- ============================================================

-- ------------------------------------------------------------
-- アクセスログ本体
-- ------------------------------------------------------------
create table if not exists access_logs (
    id            bigint generated always as identity primary key,
    ts            timestamptz not null default now(),
    ip            inet,
    country_code  char(2),
    country_name  text,
    city          text,
    latitude      double precision,
    longitude     double precision,
    path          text,
    method        text,
    status_code   int,
    user_agent    text,
    referer       text,
    is_suspicious boolean default false
);

-- 監視対象URL（site）列の追加
-- 既に access_logs がある場合は、この1行が列を足します。
alter table access_logs add column if not exists site text;

-- ------------------------------------------------------------
-- 索引：時系列の絞り込みと国別・対象別集計を速くする
-- ------------------------------------------------------------
create index if not exists idx_access_logs_ts
    on access_logs (ts desc);

create index if not exists idx_access_logs_country
    on access_logs (country_code);

create index if not exists idx_access_logs_site
    on access_logs (site);

create index if not exists idx_access_logs_suspicious
    on access_logs (is_suspicious) where is_suspicious;

-- ------------------------------------------------------------
-- 行レベルセキュリティ：匿名の鍵からは読めないようにする
-- ------------------------------------------------------------
alter table access_logs enable row level security;

-- ※ サーバー側で使う Secret key（旧 service_role）は RLS を迂回するため、
--   ポリシーを追加しなくてもアプリからは読み書きできる。
--   ポリシーを作らないことで、外部からは一切アクセスできない状態にしている。

-- ------------------------------------------------------------
-- 31日保持：古いログを消す関数
-- ------------------------------------------------------------
create or replace function purge_old_access_logs()
returns void
language sql
as $$
    delete from access_logs
    where ts < now() - interval '31 days';
$$;

-- ------------------------------------------------------------
-- 集計ビュー：直近24時間の国別
-- ------------------------------------------------------------
create or replace view v_country_stats_24h as
select country_code,
       country_name,
       count(*)  as hits,
       max(ts)   as last_seen
from access_logs
where ts > now() - interval '24 hours'
group by country_code, country_name
order by hits desc;

-- ============================================================
-- BLOCK 1 : ここまで
-- ============================================================


-- ============================================================
-- BLOCK 2（任意）：毎日 04:00 UTC に DB 側でも自動削除したい場合
--
--   手順1: Dashboard > Database > Extensions で pg_cron を有効化
--          （検索欄に cron と入力 → pg_cron を ON）
--   手順2: 有効化できたら、下の1行だけを実行
--
--   有効化しない場合、この行は実行しないでください。
--   31日より古いログはアプリ側が6時間ごとに削除します。
-- ============================================================

-- select cron.schedule('purge-access-logs', '0 4 * * *', $$ select purge_old_access_logs(); $$);


-- ============================================================
-- BLOCK 3：完了確認（結果が返れば成功）
-- ============================================================

-- select count(*) from access_logs;             -- 0 と返る
-- select * from v_country_stats_24h limit 5;    -- 空で返る
