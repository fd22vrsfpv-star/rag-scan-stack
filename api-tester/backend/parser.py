"""
parse_swagger.py — OpenAPI 3.0 JSON parser for the API Tester feature.

Resolves $ref pointers, extracts endpoints with parameters, request bodies,
responses, and security configuration from OpenAPI 3.0.x specifications.
"""

import json
import logging
from typing import Any

log = logging.getLogger(__name__)


def _resolve_ref(ref_path: str, components: dict) -> dict:
    """Resolve a $ref like '#/components/schemas/Foo' against components dict."""
    parts = ref_path.lstrip("#/").split("/")
    node = {"components": components}
    for p in parts:
        if isinstance(node, dict) and p in node:
            node = node[p]
        else:
            return {}
    return node if isinstance(node, dict) else {}


def _resolve_refs(obj: Any, components: dict, depth: int = 0) -> Any:
    """Recursively resolve all $ref pointers in an object. Max depth prevents loops."""
    if depth > 15:
        return obj
    if isinstance(obj, dict):
        if "$ref" in obj and isinstance(obj["$ref"], str):
            resolved = _resolve_ref(obj["$ref"], components)
            return _resolve_refs(resolved, components, depth + 1)
        return {k: _resolve_refs(v, components, depth + 1) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_resolve_refs(item, components, depth + 1) for item in obj]
    return obj


def _flatten_schema_fields(schema: dict, components: dict, prefix: str = "") -> list[dict]:
    """Flatten a JSON schema into a list of {name, type, required, description} fields."""
    schema = _resolve_refs(schema, components)
    fields = []
    props = schema.get("properties", {})
    required_set = set(schema.get("required", []))

    for name, prop in props.items():
        prop = _resolve_refs(prop, components)
        field_name = f"{prefix}{name}" if prefix else name
        field_type = prop.get("type", "object")
        if field_type == "array" and "items" in prop:
            items = _resolve_refs(prop["items"], components)
            field_type = f"array<{items.get('type', 'object')}>"
        fields.append({
            "name": field_name,
            "type": field_type,
            "required": name in required_set,
            "description": prop.get("description", ""),
        })
    return fields


def _extract_auth(spec: dict) -> tuple[str, dict | None]:
    """Extract primary auth type and config from securitySchemes."""
    schemes = spec.get("components", {}).get("securitySchemes", {})
    if not schemes:
        return "none", None

    for scheme_name, scheme in schemes.items():
        stype = scheme.get("type", "")
        if stype == "oauth2":
            flows = scheme.get("flows", {})
            # Prefer clientCredentials, then authorizationCode
            for flow_name in ("clientCredentials", "authorizationCode", "implicit", "password"):
                flow = flows.get(flow_name)
                if flow:
                    return "oauth2", {
                        "scheme_name": scheme_name,
                        "flow": flow_name,
                        "token_url": flow.get("tokenUrl", ""),
                        "authorization_url": flow.get("authorizationUrl", ""),
                        "scopes": flow.get("scopes", {}),
                        "description": scheme.get("description", ""),
                    }
        elif stype == "apiKey":
            return "apiKey", {
                "scheme_name": scheme_name,
                "in": scheme.get("in", "header"),
                "name": scheme.get("name", ""),
                "description": scheme.get("description", ""),
            }
        elif stype == "http":
            return "bearer", {
                "scheme_name": scheme_name,
                "scheme": scheme.get("scheme", "bearer"),
                "description": scheme.get("description", ""),
            }

    return "none", None


def _extract_parameters(params_list: list, components: dict) -> list[dict]:
    """Normalize parameter list into [{name, in, required, type, description}]."""
    result = []
    for p in params_list:
        p = _resolve_refs(p, components)
        schema = _resolve_refs(p.get("schema", {}), components)
        result.append({
            "name": p.get("name", ""),
            "in": p.get("in", "query"),
            "required": p.get("required", False),
            "type": schema.get("type", "string"),
            "format": schema.get("format", ""),
            "description": p.get("description", ""),
        })
    return result


def _extract_request_body(rb: dict, components: dict) -> dict | None:
    """Extract request body into {content_type, schema_name, required, fields}."""
    if not rb:
        return None
    rb = _resolve_refs(rb, components)
    content = rb.get("content", {})
    # Prefer application/json
    for ct in ("application/json", "text/json"):
        if ct in content:
            schema = content[ct].get("schema", {})
            schema_resolved = _resolve_refs(schema, components)
            schema_name = ""
            if "$ref" in (content[ct].get("schema") or {}):
                schema_name = content[ct]["schema"]["$ref"].split("/")[-1]
            fields = _flatten_schema_fields(schema_resolved, components)
            return {
                "content_type": ct,
                "schema_name": schema_name,
                "required": rb.get("required", False),
                "fields": fields,
            }
    # Fallback: take first content type
    if content:
        ct = next(iter(content))
        return {
            "content_type": ct,
            "schema_name": "",
            "required": rb.get("required", False),
            "fields": [],
        }
    return None


def _extract_responses(responses: dict, components: dict) -> dict:
    """Simplify responses to {status_code: {description, schema_name}}."""
    result = {}
    for code, resp in responses.items():
        resp = _resolve_refs(resp, components)
        entry = {"description": resp.get("description", "")}
        content = resp.get("content", {})
        if "application/json" in content:
            schema = content["application/json"].get("schema", {})
            if "$ref" in schema:
                entry["schema_name"] = schema["$ref"].split("/")[-1]
        result[str(code)] = entry
    return result


def parse_swagger(file_path: str) -> dict:
    """
    Parse an OpenAPI 3.0 JSON file and return normalized collection data.

    Returns:
        {
            "name": str,
            "base_url": str,
            "openapi_version": str,
            "auth_type": str,
            "auth_config": dict | None,
            "source_file": str,
            "endpoints": [
                {
                    "method": str,
                    "path": str,
                    "operation_id": str,
                    "summary": str,
                    "parameters": [...],
                    "request_body": {...} | None,
                    "responses": {...},
                    "security": [...],
                    "tags": [...]
                }
            ]
        }
    """
    with open(file_path, "r") as f:
        spec = json.load(f)

    components = spec.get("components", {})
    info = spec.get("info", {})
    servers = spec.get("servers", [])
    base_url = servers[0]["url"] if servers else ""

    auth_type, auth_config = _extract_auth(spec)

    # Extract filename from path
    source_file = file_path.rsplit("/", 1)[-1] if "/" in file_path else file_path

    endpoints = []
    global_security = spec.get("security", [])

    for path_str, path_obj in spec.get("paths", {}).items():
        # Path-level parameters apply to all operations in this path
        path_params = path_obj.get("parameters", [])

        for method in ("get", "post", "put", "delete", "patch", "head", "options"):
            operation = path_obj.get(method)
            if not operation or not isinstance(operation, dict):
                continue

            # Merge parameters: path-level + operation-level (operation wins on conflicts)
            op_params = operation.get("parameters", [])
            merged_params = {
                f"{_resolve_refs(p, components).get('name', '')}_{_resolve_refs(p, components).get('in', '')}": p
                for p in path_params
            }
            for p in op_params:
                rp = _resolve_refs(p, components)
                key = f"{rp.get('name', '')}_{rp.get('in', '')}"
                merged_params[key] = p
            params = _extract_parameters(list(merged_params.values()), components)

            # Request body
            request_body = _extract_request_body(operation.get("requestBody"), components)

            # Responses
            responses = _extract_responses(operation.get("responses", {}), components)

            # Security: operation-level overrides global
            security = operation.get("security", global_security)

            endpoints.append({
                "method": method.upper(),
                "path": path_str,
                "operation_id": operation.get("operationId", ""),
                "summary": operation.get("summary", ""),
                "parameters": params,
                "request_body": request_body,
                "responses": responses,
                "security": security,
                "tags": operation.get("tags", []),
            })

    return {
        "name": info.get("title", source_file),
        "base_url": base_url,
        "openapi_version": spec.get("openapi", "3.0.0"),
        "auth_type": auth_type,
        "auth_config": auth_config,
        "source_file": source_file,
        "endpoints": endpoints,
    }


def parse_swagger_dir(dir_path: str) -> list[dict]:
    """Parse all .json files in a directory."""
    import os
    results = []
    for fname in sorted(os.listdir(dir_path)):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(dir_path, fname)
        try:
            result = parse_swagger(fpath)
            results.append(result)
            log.info("Parsed %s: %d endpoints", fname, len(result["endpoints"]))
        except Exception as e:
            log.error("Failed to parse %s: %s", fname, e)
    return results
