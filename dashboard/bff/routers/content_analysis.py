import json
import logging
import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional, List
from config import get_settings
from engagement import engagement_headers
from utils import safe_json

router = APIRouter()
log = logging.getLogger("content_analysis")


@router.get("/api/content-extractions")
async def list_content_extractions(asset_id: str = None, scan_id: str = None, search: str = None, limit: int = 100):
    s = get_settings()
    params = {}
    if asset_id:
        params["asset_id"] = asset_id
    if scan_id:
        params["scan_id"] = scan_id
    if search:
        params["search"] = search
    params["limit"] = limit
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/content-extractions",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/content-extractions/summary")
async def content_extraction_summary(asset_id: str = None, search: str = None):
    s = get_settings()
    params = {}
    if asset_id:
        params["asset_id"] = asset_id
    if search:
        params["search"] = search
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/content-extractions/summary",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.patch("/api/content-extractions/{extraction_id}")
async def update_extraction(extraction_id: str, request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.patch(
            f"{s.rag_api_url}/content-extractions/{extraction_id}",
            json=body,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.delete("/api/content-extractions/{extraction_id}")
async def delete_extraction(extraction_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.delete(
            f"{s.rag_api_url}/content-extractions/{extraction_id}",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


# --- Patterns CRUD ---

@router.get("/api/content-intel/patterns")
async def list_patterns(category: str = None):
    s = get_settings()
    params = {}
    if category:
        params["category"] = category
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/content-intel/patterns",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/content-intel/patterns")
async def create_pattern(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/content-intel/patterns",
            json=body,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.put("/api/content-intel/patterns/{pattern_id}")
async def update_pattern(pattern_id: str, request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.put(
            f"{s.rag_api_url}/content-intel/patterns/{pattern_id}",
            json=body,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.delete("/api/content-intel/patterns/{pattern_id}")
async def delete_pattern(pattern_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.delete(
            f"{s.rag_api_url}/content-intel/patterns/{pattern_id}",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


# --- Sitemap ---

@router.get("/api/content-intel/sitemap")
async def get_sitemap(domain: str = None, asset_id: str = None):
    s = get_settings()
    params = {}
    if domain:
        params["domain"] = domain
    if asset_id:
        params["asset_id"] = asset_id
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.get(
            f"{s.rag_api_url}/content-intel/sitemap",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/content-intel/sitemap/export/urls")
async def export_sitemap_urls(domain: str = None, asset_id: str = None):
    s = get_settings()
    params = {}
    if domain: params["domain"] = domain
    if asset_id: params["asset_id"] = asset_id
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.get(
            f"{s.rag_api_url}/content-intel/sitemap/export/urls",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
    from starlette.responses import Response
    return Response(
        content=resp.content,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="urls.txt"'},
    )


@router.post("/api/wordlists/generate")
async def generate_wordlist(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=60) as c:
        resp = await c.post(
            f"{s.rag_api_url}/wordlists/generate",
            json=body,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


# --- LLM-powered credential guess generation ---

class CredentialGuessReq(BaseModel):
    login_url: str
    asset_id: Optional[str] = None
    extraction_id: Optional[str] = None


@router.post("/api/content-intel/credential-guess")
async def generate_credential_guesses(req: CredentialGuessReq):
    """
    Use the LLM to analyze content intelligence for a login page and
    generate targeted username/password guesses.

    Gathers: emails, names, tech indicators, hidden inputs, exposed keys,
    comments, and login page details. Sends to Ollama with a focused prompt
    to generate likely credentials for the target.
    """
    s = get_settings()

    # 1. Fetch content extractions for this asset/URL
    intel_context = {}
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        params = {"limit": 20}
        if req.asset_id:
            params["asset_id"] = req.asset_id
        resp = await c.get(
            f"{s.rag_api_url}/content-extractions",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code == 200:
            data = resp.json()
            extractions = data.get("extractions", [])

            # Aggregate intelligence across extractions
            all_emails = []
            all_names = []
            all_tech = []
            all_comments = []
            all_hidden = []
            all_keys = []
            all_login = []
            urls_seen = set()

            for ext in extractions:
                all_emails.extend(ext.get("emails", []))
                all_names.extend(ext.get("names", []))
                all_tech.extend(ext.get("tech_indicators", []))
                all_comments.extend(ext.get("comments", []))
                all_hidden.extend(ext.get("hidden_inputs", []))
                all_keys.extend(ext.get("exposed_keys", []))
                all_login.extend(ext.get("login_pages", []))
                urls_seen.add(ext.get("url", ""))

            intel_context = {
                "login_url": req.login_url,
                "emails": list(set(all_emails))[:30],
                "names": list(set(all_names))[:20],
                "tech_indicators": all_tech[:20],
                "comments": [c.get("content", "")[:200] for c in all_comments[:10]],
                "hidden_inputs": all_hidden[:20],
                "exposed_keys": [k.get("type", "") + ": " + k.get("value_preview", "") for k in all_keys[:10]],
                "login_pages": all_login[:5],
                "urls_sampled": list(urls_seen)[:10],
            }

    # 2. Build the LLM prompt
    prompt = f"""You are a penetration testing credential analyst. Analyze the following intelligence gathered from a web application and generate targeted username and password guesses for the login page.

TARGET LOGIN URL: {req.login_url}

INTELLIGENCE GATHERED:
- Emails found: {json.dumps(intel_context.get('emails', []))}
- Names found: {json.dumps(intel_context.get('names', []))}
- Technology stack: {json.dumps(intel_context.get('tech_indicators', []))}
- Sensitive comments: {json.dumps(intel_context.get('comments', []))}
- Hidden form inputs: {json.dumps(intel_context.get('hidden_inputs', []))}
- Exposed keys/secrets: {json.dumps(intel_context.get('exposed_keys', []))}
- Login page details: {json.dumps(intel_context.get('login_pages', []))}
- URLs sampled: {json.dumps(intel_context.get('urls_sampled', []))}

Based on this intelligence, generate:
1. Likely USERNAMES (based on emails, names, common patterns for this tech stack, default accounts)
2. Likely PASSWORDS (based on org name, tech stack defaults, common patterns, exposed secrets)

For each guess, include a brief rationale explaining why it's likely.

Respond ONLY with valid JSON in this exact format:
{{
  "usernames": [
    {{"value": "admin", "rationale": "Default admin account"}},
    {{"value": "user@example.com", "rationale": "Email found in page source"}}
  ],
  "passwords": [
    {{"value": "admin", "rationale": "Default password for admin interfaces"}},
    {{"value": "Password1!", "rationale": "Common pattern meeting complexity requirements"}}
  ],
  "analysis": "Brief summary of what was found and attack strategy"
}}"""

    # 3. Call Ollama
    try:
        # Get active model from DB or fall back to config
        model = s.ollama_model
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as c:
                r = await c.get(
                    f"{s.rag_api_url}/settings/ollama_active_model",
                    headers={"x-api-key": s.api_key, **engagement_headers()},
                )
                if r.status_code == 200:
                    m = r.json().get("value")
                    if m:
                        model = m
        except Exception:
            pass

        async with httpx.AsyncClient(verify=False, timeout=300) as c:
            try:
                resp = await c.post(
                    f"{s.ollama_url}/api/generate",
                    json={
                        "model": model,
                        "prompt": prompt,
                        "stream": False,
                        "options": {"temperature": 0.7, "num_predict": 2000},
                    },
                )
            except httpx.ReadTimeout:
                raise HTTPException(504, "LLM request timed out (model may be loading). Try again in a minute.")
            except httpx.ConnectError:
                raise HTTPException(502, "Cannot connect to Ollama. Ensure the LLM service is running.")
            if resp.status_code != 200:
                raise HTTPException(502, f"Ollama returned {resp.status_code}: {resp.text[:500]}")

            raw_response = resp.json().get("response", "")

        # 4. Parse the LLM response
        # Try to extract JSON from the response
        result = _parse_llm_json(raw_response)
        result["model"] = model
        result["intel_summary"] = {
            "emails_found": len(intel_context.get("emails", [])),
            "names_found": len(intel_context.get("names", [])),
            "tech_indicators": len(intel_context.get("tech_indicators", [])),
            "login_pages": len(intel_context.get("login_pages", [])),
        }

        return {"ok": True, **result}

    except HTTPException:
        raise
    except Exception as e:
        log.error("Credential guess generation failed: %s", e)
        raise HTTPException(500, f"LLM analysis failed: {str(e)}")


def _parse_llm_json(text: str) -> dict:
    """Extract JSON from LLM response, handling markdown code blocks."""
    # Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try extracting from code block
    import re
    json_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', text, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass

    # Try finding first { ... } block
    brace_match = re.search(r'\{[\s\S]*\}', text)
    if brace_match:
        try:
            return json.loads(brace_match.group(0))
        except json.JSONDecodeError:
            pass

    # Fallback: return raw text as analysis
    return {
        "usernames": [],
        "passwords": [],
        "analysis": text[:2000],
        "parse_error": "Could not parse LLM output as JSON",
    }
