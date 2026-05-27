window.onload = function () {
  window.ui = SwaggerUIBundle({
    urls: [
      { name: "RAG API",          url: "/specs/rag-api.yaml" },
      { name: "LLM Query",        url: "/specs/llm-query.yaml" },
      { name: "Web Scanner",      url: "/specs/web-scanner.yaml" },
      { name: "Nuclei Runner",    url: "/specs/nuclei-runner.yaml" },
      { name: "Nmap Scanner",     url: "/specs/nmap_scanner.yaml" },
      { name: "Scan Recommender", url: "/specs/scan-recommender.yaml" },
      { name: "ZAP",              url: "/specs/zap.yaml" }
    ],
    dom_id: '#swagger-ui',
    deepLinking: true,
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
    layout: "StandaloneLayout"
  });
};
