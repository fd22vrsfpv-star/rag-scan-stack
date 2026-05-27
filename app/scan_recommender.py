def ollama_query(prompt: str, model: Optional[str] = None, stream: bool = False) -> Dict:
    mdl = model or OLLAMA_MODEL
    endpoint = resolve_ollama_generate_endpoint(OLLAMA_BASE_URL)

    try:
        text = _ollama_streamed_generate(prompt, mdl, endpoint) if stream else _ollama_nonstream_generate(prompt, mdl, endpoint)
    except requests.HTTPError as e:
        # Retry once with normalized endpoint if 405
        if e.response is not None and e.response.status_code == 405:
            endpoint = resolve_ollama_generate_endpoint("http://ollama:11434")
            text = _ollama_streamed_generate(prompt, mdl, endpoint) if stream else _ollama_nonstream_generate(prompt, mdl, endpoint)
        else:
            logger.error(f"HTTP error while querying Ollama: {e.response.status_code} - {e.response.reason}")
            raise
    except requests.RequestException as e:
        logger.error(f"Request failed while querying Ollama: {e}")
        raise

    # Try to parse as JSON (since we asked model to return JSON); if not, fallback to raw text
    data = _safe_json_parse(text)
    # If the model produced {"recommendations": ...}, return as-is; otherwise unify to {"response": "..."}
    if "recommendations" in data:
        return {"model": mdl, "response": json.dumps(data)}  # return the JSON object as string
    return {"model": mdl, "response": data.get("response", text)}
