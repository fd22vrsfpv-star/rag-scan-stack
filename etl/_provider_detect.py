"""Cloud-provider detection helper used by recon ETL parsers.

Each parser passes a string of recon evidence (CNAME target, cert SAN, HTTP
server header, ASN org, etc.) and gets back a list of (provider, evidence)
tuples to apply to `assets.provider` / `assets.provider_evidence`.

Detection is intentionally substring-based and case-insensitive — same
matching strategy as the inline backfill in `db_init/ensure_all_tables.sql`,
so inline tagging and backfill stay consistent.

Add new providers here when supporting additional cloud platforms.
"""

from __future__ import annotations

# (provider, [substrings to match in lowered evidence]) — case-insensitive.
# Order doesn't matter; we return ALL providers that match.
_PROVIDER_RULES: list[tuple[str, list[str]]] = [
    ("aws", [
        "amazonaws", "cloudfront", "elasticbeanstalk", "awsapps",
        "execute-api", "elb.amazonaws", "s3.amazonaws",
        # ASN markers
        "as16509", "as14618", "as39111",
    ]),
    ("azure", [
        "azurewebsites", "cloudapp.net", "trafficmanager",
        "core.windows.net", "blob.core.windows", "onmicrosoft.com",
        "azureedge", "azure-api", "azurefd",
    ]),
    ("cloudflare", [
        "cloudflare", "cdnjs", "cloudflareaccess",
        "as13335",
    ]),
]


def detect_providers(*evidence_blobs: str) -> list[tuple[str, str]]:
    """Return [(provider, evidence_string), ...] for every provider matched.

    Pass any number of strings — they are joined and lowered before matching.
    Caller decides what constitutes evidence for a parser:

        # dnsx
        detect_providers(cname_target)
        # tlsx
        detect_providers(cert_subject_cn, cert_issuer, cert_san_list_joined)
        # httpx
        detect_providers(server_header, " ".join(tech_list))
        # asnmap
        detect_providers(asn_number, asn_org)

    The returned `evidence_string` is the matching substring + a short
    source hint (e.g. "amazonaws", "as16509"). Parsers may further
    contextualize this when writing to provider_evidence.
    """
    text = " ".join(b for b in evidence_blobs if b).lower()
    if not text:
        return []
    out: list[tuple[str, str]] = []
    for provider, needles in _PROVIDER_RULES:
        hit = next((n for n in needles if n in text), None)
        if hit:
            out.append((provider, hit))
    return out


# Atomic UPDATE template parsers can use to apply tags + evidence in one
# round-trip. Caller binds (provider, "{provider}", provider, evidence,
# asset_id) — see plan and parser usage examples.
PROVIDER_TAG_SQL = """
    UPDATE assets
    SET provider = (
            SELECT array_agg(DISTINCT v)
            FROM unnest(provider || ARRAY[%s]) v
        ),
        provider_evidence = jsonb_set(
            provider_evidence,
            %s::text[],
            COALESCE(provider_evidence->%s, '[]'::jsonb) || to_jsonb(%s::text),
            true
        )
    WHERE id = %s
"""


def tag_asset(cur, asset_id, evidence_text: str) -> int:
    """Apply provider tags to an asset based on `evidence_text`.

    Returns the number of (provider, evidence) pairs written. Safe to call
    even when no provider matches (returns 0). Parsers should call this
    once per ingested row, passing whatever string carries the cloud-hosting
    signal for that source (CNAME target, cert SAN, HTTP server header).
    """
    if not asset_id:
        return 0
    pairs = detect_providers(evidence_text)
    for provider, evidence in pairs:
        cur.execute(
            PROVIDER_TAG_SQL,
            (provider, "{" + provider + "}", provider,
             f"{evidence}:detected", str(asset_id)),
        )
    return len(pairs)
