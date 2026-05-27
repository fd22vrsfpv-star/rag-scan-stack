-- fix_scope_detection.sql
-- Script to fix incorrectly flagged out-of-scope follow-up items
-- Move URLs that are actually on in-scope domains back to correct engagements

BEGIN;

-- Step 1: Create a function to extract domain from URL/target
CREATE OR REPLACE FUNCTION extract_domain(target_url text) RETURNS text AS $$
BEGIN
    -- Handle URLs
    IF target_url LIKE 'http://%' OR target_url LIKE 'https://%' THEN
        -- Extract netloc from URL
        target_url := substring(target_url from '://([^/]+)');
    END IF;

    -- Remove port if present
    IF position(':' in target_url) > 0 THEN
        target_url := split_part(target_url, ':', 1);
    END IF;

    -- Remove path if present
    IF position('/' in target_url) > 0 THEN
        target_url := split_part(target_url, '/', 1);
    END IF;

    RETURN LOWER(target_url);
END;
$$ LANGUAGE plpgsql;

-- Step 2: Find and fix incorrectly flagged items
DO $fix_scope$
DECLARE
    unknown_scope_id uuid;
    item record;
    item_domain text;
    correct_engagement_id uuid;
    moved_count integer := 0;
BEGIN
    -- Get the unknown_scope engagement ID
    SELECT id INTO unknown_scope_id
    FROM engagements
    WHERE name = 'unknown_scope';

    IF unknown_scope_id IS NULL THEN
        RAISE NOTICE 'No unknown_scope engagement found - nothing to fix';
        RETURN;
    END IF;

    RAISE NOTICE 'Checking follow-up items in unknown_scope engagement for incorrect scope assignments...';

    -- Loop through items in unknown_scope to check if they should be moved back
    FOR item IN
        SELECT id, target, title, engagement_id
        FROM follow_up_items
        WHERE engagement_id = unknown_scope_id
          AND target IS NOT NULL
    LOOP
        -- Extract domain from the target
        item_domain := extract_domain(item.target);

        -- Skip if domain extraction failed
        CONTINUE WHEN item_domain IS NULL OR item_domain = '';

        -- Check if this domain matches any in-scope assets
        SELECT DISTINCT a.engagement_id INTO correct_engagement_id
        FROM assets a
        WHERE a.engagement_id IS NOT NULL
          AND a.engagement_id != unknown_scope_id
          AND (
            -- Exact hostname match
            LOWER(a.hostname) = item_domain
            -- Parent domain match (e.g., example.com matches sub.example.com)
            OR (a.hostname IS NOT NULL AND item_domain LIKE '%.' || LOWER(a.hostname))
            -- Subdomain match (e.g., sub.example.com matches example.com)
            OR (a.hostname IS NOT NULL AND LOWER(a.hostname) LIKE '%.' || item_domain)
          )
        LIMIT 1;

        -- If we found a matching engagement, move the item back
        IF correct_engagement_id IS NOT NULL THEN
            UPDATE follow_up_items
            SET
                engagement_id = correct_engagement_id,
                title = CASE
                    WHEN title LIKE '[OUT-OF-SCOPE] %'
                    THEN substring(title from 15)  -- Remove [OUT-OF-SCOPE] prefix
                    ELSE title
                END,
                reason = CASE
                    WHEN reason LIKE '%Auto-assigned to unknown_scope%'
                    THEN regexp_replace(reason, '\s*\(Auto-assigned to unknown_scope[^)]*\)', '', 'g')
                    ELSE reason
                END,
                tags = array_remove(array_remove(tags, 'out-of-scope'), 'unknown-scope'),
                updated_at = now()
            WHERE id = item.id;

            moved_count := moved_count + 1;
            RAISE NOTICE 'Moved item "%" (domain: %) back to correct engagement',
                         substring(item.title from 1 for 60), item_domain;
        END IF;
    END LOOP;

    RAISE NOTICE 'Fixed % incorrectly flagged out-of-scope items', moved_count;
END $fix_scope$;

-- Step 3: Show summary of what remains in unknown_scope
SELECT
    'unknown_scope' as engagement_name,
    COUNT(*) as remaining_items,
    COUNT(*) FILTER (WHERE title LIKE '[OUT-OF-SCOPE]%') as still_marked_out_of_scope,
    array_agg(DISTINCT extract_domain(target)) FILTER (WHERE extract_domain(target) IS NOT NULL) as remaining_domains
FROM follow_up_items f
JOIN engagements e ON f.engagement_id = e.id
WHERE e.name = 'unknown_scope';

-- Step 4: Cleanup
DROP FUNCTION IF EXISTS extract_domain(text);

COMMIT;