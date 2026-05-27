from pydantic_settings import BaseSettings
from functools import lru_cache
import httpx as _httpx


class Settings(BaseSettings):
    rag_api_url: str = "https://rag-api:8000"
    nmap_scanner_url: str = "https://nmap_scanner:8012"
    web_scanner_url: str = "https://web-scanner:8010"
    nuclei_url: str = "https://nuclei-runner:8011"
    pd_runner_url: str = "https://pd-runner:8023"
    osint_runner_url: str = "https://osint-runner:8024"
    exploit_runner_url: str = "https://exploit-runner:8017"
    scan_recommender_url: str = "https://scan-recommender:8013"
    autogen_url: str = "https://autogen-agents:8015"
    ollama_url: str = "http://ollama:11434"
    brutus_runner_url: str = "https://brutus-runner:8025"
    kali_listener_url: str = "https://kali-listener:8019"
    playwright_scanner_url: str = "https://playwright-scanner:8014"
    zap_url: str = "http://zap:8090"
    zap_api_key: str = "changeme"
    api_key: str = "changeme"
    ollama_model: str = "qwen2.5:14b"
    llm_backend: str = "ollama"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o"
    openai_api_base: str = "https://api.openai.com"
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-20250514"
    azure_api_key: str = ""
    azure_endpoint: str = ""
    azure_model: str = "gpt-4o"
    azure_api_version: str = "2024-08-01-preview"
    gpu_name: str = ""
    gpu_total_memory_gb: int = 0
    tunnel_manager_url: str = "https://node-manager:8027"
    node_manager_url: str = "https://node-manager:8027"  # Backward compatibility alias
    chisel_server_url: str = "http://chisel-server:10443"
    sliver_server_url: str = "http://sliver-server:31337"
    container_logs_url: str = "https://container-logs:8018"
    embedder_url: str = "https://embedder:8030"
    ssh_tunnel_host: str = "ssh-tunnel"
    ssh_tunnel_port: int = 1080
    poll_interval: int = 3
    burp_api_url: str = ""
    burp_api_key: str = ""
    burp_proxy_url: str = "http://192.168.1.181:8080"

    model_config = {"env_prefix": "", "case_sensitive": False}


@lru_cache
def get_settings() -> Settings:
    return Settings()


def http_client(timeout: int = 15) -> _httpx.AsyncClient:
    """Create an httpx client that trusts self-signed certs."""
    return _httpx.AsyncClient(timeout=timeout, verify=False)
