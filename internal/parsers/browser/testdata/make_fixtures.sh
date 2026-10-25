#!/bin/sh
# Regenerates the synthetic browser-history fixtures in this directory.
#
# The schemas are the column layouts of Chrome's History (urls, visits),
# Firefox's places.sqlite (moz_places, moz_historyvisits) and Safari's
# History.db (history_items, history_visits). Every row is invented. Each
# database mixes AI-service visits with ordinary pages and look-alike hosts
# so the tests can prove that only AI-service URLs come out of the parser.
#
# Needs the sqlite3 CLI. Without it, runs the same script in a container:
#   docker run --rm -v "$PWD":/w -w /w debian:stable-slim \
#     sh -c 'apt-get update -qq && apt-get install -y -qq sqlite3 >/dev/null && sh make_fixtures.sh'
set -eu
cd "$(dirname "$0")"
rm -f chrome_History firefox_places.sqlite firefox_places.sqlite-wal firefox_places.sqlite-shm safari_History.db

# Chrome / Chromium family: microseconds since 1601-01-01 UTC.
sqlite3 chrome_History <<'SQL'
CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
INSERT INTO meta VALUES('version','70');
CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT,url LONGVARCHAR,title LONGVARCHAR,visit_count INTEGER DEFAULT 0 NOT NULL,typed_count INTEGER DEFAULT 0 NOT NULL,last_visit_time INTEGER NOT NULL,hidden INTEGER DEFAULT 0 NOT NULL);
CREATE TABLE visits(id INTEGER PRIMARY KEY AUTOINCREMENT,url INTEGER NOT NULL,visit_time INTEGER NOT NULL,from_visit INTEGER,external_referrer_url TEXT,transition INTEGER DEFAULT 0 NOT NULL,segment_id INTEGER,visit_duration INTEGER DEFAULT 0 NOT NULL,incremented_omnibox_typed_score BOOLEAN DEFAULT FALSE NOT NULL,opener_visit INTEGER,originator_cache_guid TEXT,originator_visit_id INTEGER,originator_from_visit INTEGER,originator_opener_visit INTEGER,is_known_to_sync BOOLEAN DEFAULT FALSE NOT NULL,consider_for_ntp_most_visited BOOLEAN DEFAULT FALSE NOT NULL,visited_link_id INTEGER DEFAULT 0 NOT NULL,app_id TEXT);
CREATE INDEX visits_url_index ON visits (url);
CREATE TEMP VIEW t AS SELECT (strftime('%s','2026-10-20 10:00:00') + 11644473600) * 1000000 AS base;
INSERT INTO urls(id,url,title,visit_count,typed_count,last_visit_time) VALUES
 (1,'https://chatgpt.com/c/6710aa00-1111-2222-3333-444455556666','Quarterly numbers cleanup',3,1,0),
 (2,'https://chatgpt.com/share/6710bb00-aaaa-bbbb-cccc-ddddeeeeffff','Deploy key rotation',1,0,0),
 (3,'https://claude.ai/chat/0b6f2a3c-1d2e-4f50-8a9b-0c1d2e3f4a5b','Refactor auth middleware - Claude',2,0,0),
 (4,'https://www.example.com/private-page','My bank statement',2,0,0),
 (5,'https://gemini.google.com/app/a1b2c3d4e5f6','Gemini',1,0,0),
 (6,'https://chat.deepseek.com/a/chat/s/9f8e7d6c-1234','DeepSeek - Into the Unknown',1,0,0),
 (7,'https://www.perplexity.ai/search/how-to-rotate-aws-keys-AbC123','how to rotate aws keys',1,0,0),
 (8,'https://x.com/i/grok?conversation=1850000000000000001','Grok / X',1,0,0),
 (9,'https://mail.google.com/mail/u/0/#inbox','Inbox (3)',1,0,0),
 (10,'https://evil.example/?q=https://chatgpt.com/c/fake','search',1,0,0),
 (11,'https://chatgpt.com.evil.example/c/lookalike','lookalike',1,0,0),
 (12,'https://platform.openai.com/api-keys','API keys - OpenAI API',1,1,0);
INSERT INTO visits(id,url,visit_time,from_visit,transition,visit_duration) VALUES
 (1,1,(SELECT base FROM t),0,805306369,60000000),
 (2,1,(SELECT base FROM t)+600000000,0,0,1000000),
 (3,1,(SELECT base FROM t)+7200000000,0,8,0),
 (4,2,(SELECT base FROM t)+900000000,2,0,0),
 (5,3,(SELECT base FROM t)+1200000000,0,1,0),
 (6,3,(SELECT base FROM t)+1500000000,5,0,0),
 (7,4,(SELECT base FROM t)+1600000000,0,1,0),
 (8,4,(SELECT base FROM t)+1700000000,0,0,0),
 (9,5,(SELECT base FROM t)+1800000000,0,0,0),
 (10,6,(SELECT base FROM t)+1900000000,0,0,0),
 (11,7,(SELECT base FROM t)+2000000000,0,0,0),
 (12,8,(SELECT base FROM t)+2100000000,0,0,0),
 (13,9,(SELECT base FROM t)+2200000000,0,0,0),
 (14,10,(SELECT base FROM t)+2300000000,0,0,0),
 (15,11,(SELECT base FROM t)+2400000000,0,0,0),
 (16,12,(SELECT base FROM t)+2500000000,0,1,0);
UPDATE urls SET last_visit_time = (SELECT max(visit_time) FROM visits WHERE visits.url = urls.id);
SQL

# Firefox: PRTime, microseconds since the Unix epoch. Written in WAL mode;
# the second batch of rows lives only in the -wal file, as on a running
# browser, so the parser must apply the log to see them.
sqlite3 firefox_places.sqlite <<'SQL'
PRAGMA journal_mode=WAL;
PRAGMA wal_autocheckpoint=0;
CREATE TABLE moz_origins (id INTEGER PRIMARY KEY, prefix TEXT NOT NULL, host TEXT NOT NULL, frecency INTEGER NOT NULL, recalc_frecency INTEGER NOT NULL DEFAULT 0, alt_frecency INTEGER, recalc_alt_frecency INTEGER NOT NULL DEFAULT 0, UNIQUE (prefix, host));
CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, rev_host LONGVARCHAR, visit_count INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0 NOT NULL, typed INTEGER DEFAULT 0 NOT NULL, frecency INTEGER DEFAULT -1 NOT NULL, last_visit_date INTEGER , guid TEXT, foreign_count INTEGER DEFAULT 0 NOT NULL, url_hash INTEGER DEFAULT 0 NOT NULL , description TEXT, preview_image_url TEXT, site_name TEXT, origin_id INTEGER REFERENCES moz_origins(id), recalc_frecency INTEGER NOT NULL DEFAULT 0, alt_frecency INTEGER, recalc_alt_frecency INTEGER NOT NULL DEFAULT 0);
CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER, session INTEGER, source INTEGER DEFAULT 0 NOT NULL, triggeringPlaceId INTEGER);
CREATE TEMP VIEW t AS SELECT strftime('%s','2026-10-21 08:00:00') * 1000000 AS base;
INSERT INTO moz_places(id,url,title,visit_count,typed,last_visit_date,guid) VALUES
 (1,'https://claude.ai/project/0199aaaa-bbbb-7ccc-8ddd-eeeeffff0000','Incident notes project',1,0,0,'g1'),
 (2,'https://poe.com/s/Ab12Cd34Ef56','Shared Poe chat',1,0,0,'g2'),
 (3,'https://news.example.org/story','Some news',1,0,0,'g3');
INSERT INTO moz_historyvisits(id,from_visit,place_id,visit_date,visit_type) VALUES
 (1,0,1,(SELECT base FROM t),2),
 (2,0,2,(SELECT base FROM t)+60000000,1),
 (3,0,3,(SELECT base FROM t)+120000000,1);
PRAGMA wal_checkpoint(TRUNCATE);
INSERT INTO moz_places(id,url,title,visit_count,typed,last_visit_date,guid) VALUES
 (4,'https://huggingface.co/chat/conversation/66ffeedd0011223344556677','HuggingChat',1,0,0,'g4'),
 (5,'https://chat.mistral.ai/chat/7c1e9a52-0d3b-4f6e-9a1c-2b3d4e5f6a7b','Le Chat - Mistral AI',1,0,0,'g5');
INSERT INTO moz_historyvisits(id,from_visit,place_id,visit_date,visit_type) VALUES
 (4,0,4,(SELECT base FROM t)+180000000,1),
 (5,0,5,(SELECT base FROM t)+240000000,2);
.shell cp firefox_places.sqlite firefox_places.sqlite.snap
.shell cp firefox_places.sqlite-wal firefox_places.sqlite-wal.snap
SQL
mv firefox_places.sqlite.snap firefox_places.sqlite
mv firefox_places.sqlite-wal.snap firefox_places.sqlite-wal
rm -f firefox_places.sqlite-shm

# Safari: Cocoa time, seconds (REAL) since 2001-01-01 UTC. Titles are on
# the visit rows.
sqlite3 safari_History.db <<'SQL'
CREATE TABLE history_items (id INTEGER PRIMARY KEY AUTOINCREMENT,url TEXT NOT NULL UNIQUE,domain_expansion TEXT NULL,visit_count INTEGER NOT NULL,daily_visit_counts BLOB NOT NULL,weekly_visit_counts BLOB NULL,autocomplete_triggers BLOB NULL,should_recompute_derived_visit_counts INTEGER NOT NULL,visit_count_score INTEGER NOT NULL,status_code INTEGER NOT NULL DEFAULT 0);
CREATE TABLE history_visits (id INTEGER PRIMARY KEY AUTOINCREMENT,history_item INTEGER NOT NULL REFERENCES history_items(id) ON DELETE CASCADE,visit_time REAL NOT NULL,title TEXT NULL,load_successful BOOLEAN NOT NULL DEFAULT 1,http_non_get BOOLEAN NOT NULL DEFAULT 0,synthesized BOOLEAN NOT NULL DEFAULT 0,redirect_source INTEGER NULL UNIQUE REFERENCES history_visits(id) ON DELETE CASCADE,redirect_destination INTEGER NULL UNIQUE REFERENCES history_visits(id) ON DELETE CASCADE,origin INTEGER NOT NULL DEFAULT 0,generation INTEGER NOT NULL DEFAULT 0,attributes INTEGER NOT NULL DEFAULT 0,score INTEGER NOT NULL DEFAULT 0);
CREATE TEMP VIEW t AS SELECT strftime('%s','2026-10-22 12:00:00') - 978307200 + 0.5 AS base;
INSERT INTO history_items(id,url,domain_expansion,visit_count,daily_visit_counts,should_recompute_derived_visit_counts,visit_count_score) VALUES
 (1,'https://copilot.microsoft.com/chats/AbCdEf123456','copilot.microsoft',2,x'00',0,0),
 (2,'https://m365.cloud.microsoft/chat/?auth=2','m365.cloud.microsoft',1,x'00',0,0),
 (3,'https://notebooklm.google.com/notebook/5e6f7a8b-1c2d-3e4f-5a6b-7c8d9e0f1a2b','notebooklm.google',1,x'00',0,0),
 (4,'https://shop.example.net/cart','shop.example',1,x'00',0,0);
INSERT INTO history_visits(id,history_item,visit_time,title) VALUES
 (1,1,(SELECT base FROM t),'Copilot: Draft vendor email'),
 (2,1,(SELECT base FROM t)+3600,'Copilot: Draft vendor email'),
 (3,2,(SELECT base FROM t)+60,'Microsoft 365 Copilot'),
 (4,3,(SELECT base FROM t)+120,'Threat model notebook - NotebookLM'),
 (5,4,(SELECT base FROM t)+180,'Your cart');
SQL
ls -l chrome_History firefox_places.sqlite firefox_places.sqlite-wal safari_History.db
