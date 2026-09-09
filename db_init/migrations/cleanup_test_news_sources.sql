-- =============================================================================
-- cleanup_test_news_sources.sql
--
-- Remove (1) test entries that accumulated in news_sources during development
-- and (2) old URLs that are superseded by the new defaults in
-- ensure_all_tables.sql (verified-working URLs replaced earlier variants
-- for Dark Reading and The Hacker News; CyberSecurityNews was dropped
-- entirely).  Apply BEFORE re-running the seed so the new entries land
-- cleanly without "duplicate by name" rows.
--
-- Filtering by exact URL (not pattern) so we never accidentally delete
-- a legitimate source.  Idempotent: re-running is a no-op once the
-- rows are gone.
--
-- Run order:
--   1) psql -f cleanup_test_news_sources.sql   (delete stale rows)
--   2) psql -f ensure_all_tables.sql           (insert new defaults)
-- =============================================================================

-- Category 1: development test entries (made-up domains, never served real data)
DELETE FROM public.news_sources
WHERE url IN (
    'https://anothertestdomain99999.com/feed',
    'https://finaltestdomain88888.com/feed',
    'https://mytestdomain12345.com/feed',
    'https://example.com/feed.rss',
    'https://test-unique-123456.com/feed.rss'
);

-- Category 2: URLs from the old default seed superseded by ensure_all_tables.sql.
-- Removing these before the seed re-runs avoids "two entries per publisher"
-- (one with the old URL, one with the new).
DELETE FROM public.news_sources
WHERE url IN (
    'https://thehackernews.com/feeds/posts/default',   -- replaced by feedburner URL
    'https://www.darkreading.com/rss/all.xml',         -- replaced by /rss.xml
    'https://www.cybersecuritynews.com/feed/'          -- dropped from new seed
);
