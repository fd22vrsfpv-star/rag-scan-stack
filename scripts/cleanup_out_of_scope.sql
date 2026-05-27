-- cleanup_out_of_scope.sql
-- Script to clean up existing out-of-scope follow-up items and move them to unknown_scope engagement

BEGIN;

-- Step 1: Create unknown_scope engagement if it doesn't exist
DO $create_engagement$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM engagements WHERE name = 'unknown_scope') THEN
        INSERT INTO engagements (
            id, name, client, engagement_type, status, scope_name,
            notes, start_date, created_at, updated_at
        )
        VALUES (
            gen_random_uuid(),
            'unknown_scope',
            'System',
            'other',
            'active',
            'Out-of-scope discoveries',
            'Auto-created engagement for out-of-scope discoveries during OSINT scanning. Contains domains and targets discovered during reconnaissance that are outside the primary engagement scope.',
            now(),
            now(),
            now()
        );
        RAISE NOTICE 'Created unknown_scope engagement';
    ELSE
        RAISE NOTICE 'unknown_scope engagement already exists';
    END IF;
END $create_engagement$;

-- Step 2: Get the unknown_scope engagement ID and move out-of-scope items
DO $cleanup$
DECLARE
    unknown_scope_id uuid;
    updated_count integer;
BEGIN
    -- Get the unknown_scope engagement ID
    SELECT id INTO unknown_scope_id
    FROM engagements
    WHERE name = 'unknown_scope';

    IF unknown_scope_id IS NULL THEN
        RAISE EXCEPTION 'Failed to create or find unknown_scope engagement';
    END IF;

    -- Update out-of-scope follow-ups with common external domain patterns
    UPDATE follow_up_items
    SET
        engagement_id = unknown_scope_id,
        title = CASE
            WHEN title LIKE '[OUT-OF-SCOPE]%' THEN title
            ELSE '[OUT-OF-SCOPE] ' || title
        END,
        reason = CASE
            WHEN reason LIKE '%Auto-assigned to unknown_scope%' THEN reason
            ELSE reason || ' (Auto-assigned to unknown_scope - discovered during reconnaissance)'
        END,
        tags = CASE
            WHEN 'out-of-scope' = ANY(tags) THEN tags
            ELSE array_append(array_append(tags, 'out-of-scope'), 'unknown-scope')
        END,
        severity = CASE
            WHEN severity = 'critical' THEN 'medium'
            WHEN severity = 'high' THEN 'low'
            ELSE severity
        END,
        updated_at = now()
    WHERE engagement_id IS NULL
      AND (
        target ILIKE '%demo.testfire.net%' OR
        target ILIKE '%addons.mozilla.org%' OR
        target ILIKE '%mozilla.org%' OR
        target ILIKE '%github.com%' OR
        target ILIKE '%stackoverflow.com%' OR
        target ILIKE '%w3.org%' OR
        target ILIKE '%google.com%' OR
        target ILIKE '%microsoft.com%' OR
        target ILIKE '%apple.com%' OR
        target ILIKE '%facebook.com%' OR
        target ILIKE '%twitter.com%' OR
        target ILIKE '%linkedin.com%' OR
        target ILIKE '%youtube.com%' OR
        target ILIKE '%cdn.%' OR
        target ILIKE '%.googleapis.com%' OR
        target ILIKE '%.gstatic.com%'
      );

    GET DIAGNOSTICS updated_count = ROW_COUNT;
    RAISE NOTICE 'Updated % out-of-scope follow-up items and assigned to unknown_scope engagement', updated_count;

END $cleanup$;

-- Step 3: Show summary of cleanup
SELECT
    'unknown_scope' as engagement_name,
    COUNT(*) as follow_up_count,
    COUNT(*) FILTER (WHERE title LIKE '[OUT-OF-SCOPE]%') as marked_out_of_scope,
    COUNT(*) FILTER (WHERE 'out-of-scope' = ANY(tags)) as tagged_out_of_scope
FROM follow_up_items f
JOIN engagements e ON f.engagement_id = e.id
WHERE e.name = 'unknown_scope';

COMMIT;