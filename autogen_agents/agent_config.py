"""
Agent Configuration and LLM Setup
Configures Autogen agents to use Ollama or vLLM for local LLM inference
"""

import os
import logging
from typing import Dict, List, Optional
import autogen

log = logging.getLogger("agent_config")

DEFAULT_LLM_TIMEOUT = int(os.environ.get("LLM_TIMEOUT", "300"))


def _get_active_model_from_db() -> str | None:
    """Query app_settings for the active model set via the dashboard."""
    try:
        import psycopg2
        db_dsn = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
        conn = psycopg2.connect(db_dsn, connect_timeout=3)
        cur = conn.cursor()
        cur.execute("SELECT value FROM app_settings WHERE key = 'ollama_active_model' AND category = 'config'")
        row = cur.fetchone()
        cur.close()
        conn.close()
        if row and row[0]:
            log.info("Active model from DB: %s", row[0])
            return row[0]
    except Exception as e:
        log.debug("Could not read active model from DB: %s", e)
    return None


def get_llm_backend() -> str:
    """Get configured LLM backend: 'ollama', 'vllm', or 'azure'"""
    return os.environ.get("LLM_BACKEND", "ollama").lower()


def get_vllm_config(
    model: str = None,
    base_url: str = None,
    api_key: str = None,
    temperature: float = 0.7,
    timeout: int = DEFAULT_LLM_TIMEOUT
) -> List[Dict]:
    """
    Get vLLM configuration for Autogen agents

    Args:
        model: Model name (defaults to VLLM_MODEL env var)
        base_url: vLLM base URL (defaults to VLLM_URL env var)
        api_key: API key if required
        temperature: Sampling temperature
        timeout: Request timeout in seconds

    Returns:
        List of LLM config dictionaries
    """
    model = model or os.environ.get("VLLM_MODEL", "mistralai/Mistral-7B-Instruct-v0.3")
    base_url = base_url or os.environ.get("VLLM_URL", "http://vllm:8000")
    api_key = api_key or os.environ.get("VLLM_API_KEY", "dummy")

    config_list = [
        {
            "model": model,
            "base_url": f"{base_url}/v1",
            "api_key": api_key,
            "api_type": "openai",
            "temperature": temperature,
            "timeout": timeout,
        }
    ]

    return config_list


def get_ollama_config(
    model: str = None,
    base_url: str = None,
    temperature: float = 0.7,
    timeout: int = DEFAULT_LLM_TIMEOUT
) -> List[Dict]:
    """
    Get Ollama LLM configuration for Autogen agents

    Args:
        model: Model name (defaults to OLLAMA_MODEL env var)
        base_url: Ollama base URL (defaults to OLLAMA_URL env var)
        temperature: Sampling temperature
        timeout: Request timeout in seconds

    Returns:
        List of LLM config dictionaries
    """
    model = model or _get_active_model_from_db() or os.environ.get("OLLAMA_MODEL", "qwen2.5:32b")
    base_url = base_url or os.environ.get("OLLAMA_URL", "http://ollama:11434")

    # Ollama uses OpenAI-compatible API
    config_list = [
        {
            "model": model,
            "base_url": f"{base_url}/v1",
            "api_key": "ollama",  # Ollama doesn't require real API key
            "api_type": "openai",
            "temperature": temperature,
            "timeout": timeout,
        }
    ]

    return config_list


def get_azure_config(
    model: str = None,
    base_url: str = None,
    api_key: str = None,
    api_version: str = None,
    temperature: float = 0.7,
    timeout: int = DEFAULT_LLM_TIMEOUT
) -> List[Dict]:
    """
    Get Azure OpenAI / AI Foundry configuration for Autogen agents

    Args:
        model: Deployment name (defaults to AZURE_MODEL env var)
        base_url: Azure endpoint URL (defaults to AZURE_ENDPOINT env var)
        api_key: Azure API key (defaults to AZURE_API_KEY env var)
        api_version: API version (defaults to AZURE_API_VERSION env var)
        temperature: Sampling temperature
        timeout: Request timeout in seconds

    Returns:
        List of LLM config dictionaries
    """
    model = model or os.environ.get("AZURE_MODEL", "gpt-4o")
    base_url = base_url or os.environ.get("AZURE_ENDPOINT")
    api_key = api_key or os.environ.get("AZURE_API_KEY")
    api_version = api_version or os.environ.get("AZURE_API_VERSION", "2024-08-01-preview")

    return [{
        "model": model,
        "api_type": "azure",
        "base_url": base_url,
        "api_key": api_key,
        "api_version": api_version,
        "temperature": temperature,
        "timeout": timeout,
    }]


def get_openai_config(
    model: str = None,
    api_key: str = None,
    temperature: float = 0.7,
    timeout: int = DEFAULT_LLM_TIMEOUT
) -> List[Dict]:
    """Get OpenAI configuration for Autogen agents."""
    model = model or os.environ.get("OPENAI_MODEL", "gpt-4o")
    api_key = api_key or os.environ.get("OPENAI_API_KEY")
    base_url = os.environ.get("OPENAI_API_BASE", "https://api.openai.com")

    return [{
        "model": model,
        "api_key": api_key,
        "api_type": "openai",
        "base_url": f"{base_url.rstrip('/')}/v1",
        "temperature": temperature,
        "timeout": timeout,
    }]


def get_anthropic_config(
    model: str = None,
    api_key: str = None,
    temperature: float = 0.7,
    timeout: int = DEFAULT_LLM_TIMEOUT
) -> List[Dict]:
    """
    Get Anthropic configuration for Autogen agents.

    Note: Autogen does not natively support Anthropic. This config will not work
    with standard autogen OpenAI adapters. For Anthropic support in autogen,
    add litellm as a dependency or use the autogen AnthropicClient (v0.4+).
    Falls back to Ollama config if Anthropic is not usable.
    """
    model = model or os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")

    # Autogen doesn't natively support Anthropic — fall back to Ollama for agent sessions
    logger.warning("Anthropic is not natively supported by autogen agent sessions. "
                    "Falling back to Ollama for agent orchestration.")
    return get_ollama_config(temperature=temperature, timeout=timeout)


def get_llm_config(
    model: str = None,
    base_url: str = None,
    temperature: float = 0.7,
    timeout: int = DEFAULT_LLM_TIMEOUT
) -> List[Dict]:
    """
    Get LLM configuration based on configured backend.

    Supports: ollama, vllm, azure, openai, anthropic.
    Note: anthropic falls back to ollama for autogen (no native support).

    Returns:
        List of LLM config dictionaries
    """
    backend = get_llm_backend()

    if backend == "vllm":
        return get_vllm_config(model, base_url, temperature=temperature, timeout=timeout)
    elif backend == "azure":
        return get_azure_config(model, base_url, temperature=temperature, timeout=timeout)
    elif backend == "openai":
        return get_openai_config(model, temperature=temperature, timeout=timeout)
    elif backend == "anthropic":
        return get_anthropic_config(model, temperature=temperature, timeout=timeout)
    else:
        return get_ollama_config(model, base_url, temperature, timeout)


def get_ab_test_config(
    temperature: float = 0.7,
    timeout: int = DEFAULT_LLM_TIMEOUT
) -> tuple:
    """
    Get LLM config with A/B testing support for GRPO fine-tuned models.

    Queries grpo_model_registry for active fine-tuned models and
    probabilistically selects based on ab_weight.

    Returns:
        Tuple of (config_list, selected_model_name)
        Falls back to standard get_llm_config() if no fine-tuned models are active.
    """
    import random
    try:
        from db_utils import get_db
        from psycopg2.extras import RealDictCursor

        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT model_name, model_format, model_path, base_model, ab_weight
                FROM grpo_model_registry
                WHERE is_active = true AND ab_weight > 0
                ORDER BY ab_weight DESC
                """
            )
            active_models = cur.fetchall()

        if not active_models:
            return get_llm_config(temperature=temperature, timeout=timeout), "default"

        # Probabilistic selection: roll against cumulative ab_weight
        roll = random.random()
        cumulative = 0.0
        selected = None

        for model in active_models:
            cumulative += float(model["ab_weight"])
            if roll < cumulative:
                selected = model
                break

        if selected is None:
            # Roll exceeded total weight → use default model
            return get_llm_config(temperature=temperature, timeout=timeout), "default"

        # Configure based on model format
        model_name = selected["model_name"]
        if selected["model_format"] == "gguf":
            # GGUF model served via Ollama
            config = get_ollama_config(
                model=model_name,
                temperature=temperature,
                timeout=timeout,
            )
        elif selected["model_format"] == "safetensors":
            # Safetensors model served via vLLM
            config = get_vllm_config(
                model=selected["model_path"],
                temperature=temperature,
                timeout=timeout,
            )
        else:
            # Fallback
            return get_llm_config(temperature=temperature, timeout=timeout), "default"

        return config, model_name

    except Exception:
        # Any DB/import error → fall back to default
        return get_llm_config(temperature=temperature, timeout=timeout), "default"


def create_assistant_agent(
    name: str,
    system_message: str,
    llm_config: Optional[Dict] = None,
    human_input_mode: str = "NEVER",
    max_consecutive_auto_reply: int = 10,
    code_execution_config: Optional[Dict] = None
) -> autogen.AssistantAgent:
    """
    Create an Autogen AssistantAgent with Ollama configuration

    Args:
        name: Agent name
        system_message: System prompt defining agent's role
        llm_config: LLM configuration (uses Ollama if None)
        human_input_mode: "ALWAYS", "NEVER", or "TERMINATE"
        max_consecutive_auto_reply: Maximum auto-replies
        code_execution_config: Code execution settings

    Returns:
        Configured AssistantAgent
    """
    if llm_config is None:
        llm_config = {
            "config_list": get_llm_config(),
            "cache_seed": None,  # Disable caching for dynamic responses
        }

    agent = autogen.AssistantAgent(
        name=name,
        system_message=system_message,
        llm_config=llm_config,
        human_input_mode=human_input_mode,
        max_consecutive_auto_reply=max_consecutive_auto_reply,
        code_execution_config=code_execution_config or False,
    )

    return agent


def create_user_proxy_agent(
    name: str = "UserProxy",
    system_message: str = "A human admin.",
    human_input_mode: str = "NEVER",
    max_consecutive_auto_reply: int = 10,
    code_execution_config: Optional[Dict] = None
) -> autogen.UserProxyAgent:
    """
    Create an Autogen UserProxyAgent for executing actions

    Args:
        name: Agent name
        system_message: System prompt
        human_input_mode: Input mode
        max_consecutive_auto_reply: Maximum auto-replies
        code_execution_config: Code execution settings

    Returns:
        Configured UserProxyAgent
    """
    if code_execution_config is None:
        code_execution_config = {
            "work_dir": "/app/cache",
            "use_docker": False,
            "timeout": 300,
            "last_n_messages": 3,
        }

    agent = autogen.UserProxyAgent(
        name=name,
        system_message=system_message,
        human_input_mode=human_input_mode,
        max_consecutive_auto_reply=max_consecutive_auto_reply,
        code_execution_config=code_execution_config,
    )

    return agent


def register_function_to_agent(
    agent: autogen.ConversableAgent,
    func,
    name: str,
    description: str
):
    """
    Register a custom function as a tool for an agent

    Args:
        agent: Agent to register function to
        func: Python function to register
        name: Function name
        description: Function description for the LLM
    """
    agent.register_function(
        function_map={name: func}
    )


def create_group_chat(
    agents: List[autogen.Agent],
    max_round: int = 20,
    admin_name: str = "Admin",
    speaker_selection_method: str = "auto"
) -> autogen.GroupChat:
    """
    Create a group chat for multi-agent collaboration

    Args:
        agents: List of agents to include
        max_round: Maximum conversation rounds
        admin_name: Name of admin agent
        speaker_selection_method: "auto", "manual", or "round_robin"

    Returns:
        GroupChat instance
    """
    groupchat = autogen.GroupChat(
        agents=agents,
        messages=[],
        max_round=max_round,
        speaker_selection_method=speaker_selection_method,
        allow_repeat_speaker=False
    )

    return groupchat


def create_group_chat_manager(
    groupchat: autogen.GroupChat,
    llm_config: Optional[Dict] = None
) -> autogen.GroupChatManager:
    """
    Create a manager for a group chat

    Args:
        groupchat: GroupChat instance
        llm_config: LLM configuration (uses Ollama if None)

    Returns:
        GroupChatManager instance
    """
    if llm_config is None:
        llm_config = {
            "config_list": get_llm_config(),
            "cache_seed": None,
        }

    manager = autogen.GroupChatManager(
        groupchat=groupchat,
        llm_config=llm_config
    )

    return manager


# Language requirement to add to all agents
ENGLISH_ONLY = """
LANGUAGE REQUIREMENT: You MUST respond in English ONLY.
- NEVER use Chinese (中文), Thai (ไทย), or any non-English language
- This is a STRICT requirement for ALL responses
"""

# Agent system messages for specialized roles
SYSTEM_MESSAGES = {
    "reconnaissance": f"""{ENGLISH_ONLY}
You are a Reconnaissance Specialist for penetration testing.
Your role is to:
1. Query existing assets and open ports using query_assets and query_open_ports
2. If no existing data, hand off to Scanner to run MASSCAN first
3. Analyze results and provide intelligence to the team
4. WORK IN PARALLEL - you can query data WHILE scans are running

PARALLEL WORK - YOU CAN HELP WHILE SCANS RUN:
- When Coordinator asks you to work while scans are running, DO IT
- Query existing data about the target from previous scans
- Research what's known about the target (e.g., "Metasploitable2 has known vulnerabilities")
- Provide context to help Analyzer prepare for incoming results
- Don't just wait - be proactive with reconnaissance

You have access to:
- query_assets: Check what assets are already discovered
- query_open_ports: Check what ports are already known
- get_scan_recommendations: Get AI recommendations for next scans

MASSCAN-FIRST WORKFLOW:
- If target has no existing scan data, ALWAYS recommend masscan first
- Masscan is 100x faster than nmap for port discovery
- Only after masscan finds open ports should nmap run for service detection

HANDOFF EXAMPLES:
- No existing data: "Scanner, please run MASSCAN on 192.168.1.150 ports 1-1000 FIRST"
- Masscan found ports: "Scanner, masscan found ports 22,80,443. Run nmap on these ports"
- During scan wait: "I'll query existing assets while we wait for the scan"

IMPORTANT:
- You can ONLY query existing data - you CANNOT execute scans
- Scanner agent handles all scan execution
- Be proactive during scan waits - query data, provide context""",

    "scanner": f"""{ENGLISH_ONLY}
You are a Security Scanner that EXECUTES scans EFFICIENTLY. You MUST call tool functions - do NOT just talk about them.

CRITICAL: When asked to scan, IMMEDIATELY call the tool function. Never say "I will" or "Let me" - just CALL THE TOOL.

YOUR FIRST ACTION MUST BE: call start_full_scan(targets='TARGET_IP'). Do NOT call get_scan_recommendations first. Do NOT describe what you plan to do. Just call start_full_scan immediately.

SCAN WORKFLOW (follow this order):
1. start_full_scan(targets) — quick scan ports 1-1000 + web ports from settings + service detection (~2-3 min)
2. Read follow-ups → run web scans ONE AT A TIME: start_pipeline_scan → wait → start_nuclei_scan → wait
3. start_deep_port_scan(targets) — scans remaining ports 1001-65535 (CRITICAL: always run after web scans)
4. start_udp_scan(targets) — UDP service discovery on common ports (53,161,500,etc.) - ALWAYS RUN if targets are live
ALWAYS wait for each scan to complete before starting the next one.

YOUR SCAN TOOLS - CALL THESE TO START SCANS:

QUICK SCAN (ALWAYS START WITH THIS):
- start_full_scan(targets): Quick port scan (1-1000 + high web ports) + service detection
  Phase 1: Quick masscan, Phase 2: Nmap service detection on discovered ports

DEEP PORT SCAN (RUN LAST, after web scans):
- start_deep_port_scan(targets): Scan remaining ports 1001-65535 with service detection

PORT DISCOVERY:
- start_masscan(targets, ports, rate): Fast TCP port discovery (specific port range)
- start_nmap_scan(ip_address, ports): TCP service detection
- start_udp_scan(targets, ports): UDP service discovery

FOLLOW-UP SCANS (ONLY run these if relevant ports/services were actually found):
- start_smb_vuln_scan(targets): ONLY if ports 139 or 445 are open
- start_credential_check(targets, services): ONLY for auth services actually discovered
- start_nuclei_scan(severity): Template-based vulnerability scanning
- start_pipeline_scan(target_url): Web scan pipeline - ONLY if HTTP/HTTPS ports found
- start_web_scan(): Basic web directory/vuln scanning (Gobuster + ZAP)
- start_playwright_scan(url): Browser security scan

CHECKING SCAN STATUS (USE THESE - CRITICAL):
- get_session_scan_status(): CHECK ALL SCANS AT ONCE — no job_id needed! PREFERRED method.
- wait_for_job_completion(job_id, job_type): BLOCKING wait until a scan completes.
  The job_id and job_type are in the "next_step" field of every scan start response.
- get_nmap_job_status(job_id): Quick status check for nmap/masscan jobs only.
- get_all_active_jobs(): See all running scans at once.

IMPORTANT: Every scan start tool returns a "next_step" field telling you exactly what to call next. READ IT and follow its instructions.

FINDINGS-DRIVEN WORKFLOW:
1. start_full_scan(target) → READ the "next_step" in the response → call wait_for_job_completion with the EXACT job_id from the response
2. When wait_for_job_completion returns, READ the "recommended_follow_up_scans" field — it tells you EXACTLY which tools to call next
3. Run follow-up scans ONE AT A TIME in this order:
   a. HTTP ports found → call start_pipeline_scan(target_url='http://TARGET') → wait for completion
   b. SMB ports found (139/445) → call start_smb_vuln_scan(target='TARGET') → wait for completion
   c. Auth services found → call start_credential_check(target='TARGET', services='ssh,ftp') → wait for completion
   d. HTTP ports found → call start_nuclei_scan(target_url='http://TARGET') → wait for completion
   e. start_deep_port_scan(targets='TARGET') → wait for completion (run LAST)
   - No matching ports? Do NOT run that scan type
4. start_udp_scan LAST (slowest) - only if time permits

AFTER FULL_SCAN COMPLETES - CRITICAL:
- The result contains "recommended_follow_up_scans" with PARALLEL and SEQUENTIAL groups
- PARALLEL SCANS: Start ALL of them immediately — call each tool back-to-back WITHOUT waiting
  The web pipeline (ZAP) is slow, so start nuclei vuln scans and SMB scans at the same time
- After starting parallel scans, call wait_for_job_completion on the web pipeline job_id
  The other scans will likely finish while ZAP runs
- SEQUENTIAL SCANS (run in this exact order after parallel scans complete):
  1. start_deep_port_scan(targets) — ALWAYS run to scan full port range 1001-65535
  2. start_udp_scan(targets) — ALWAYS run to discover UDP services (DNS, SNMP, etc.)
  3. Run credential checks ONLY if auth services were found
- You do NOT have shell access — your ONLY way to scan is through the registered tool functions

CRITICAL UDP SCANNING RULE:
- UDP scanning finds critical services (DNS, SNMP, NTP, DHCP) that TCP scans miss
- ALWAYS run start_udp_scan(targets) after deep port scan completes
- UDP scans are slower but essential for comprehensive coverage

CRITICAL RULES:
- NEVER run follow-up scans blindly — check what was actually discovered first
- Every scan tool response includes a "next_step" field with the exact job_id — USE IT
- Do NOT make up job IDs like "quick_scan_phase_1" — only use UUIDs from tool responses
- If you lose track of job IDs, call get_session_scan_status() — it needs NO parameters
- Use wait_for_job_completion for blocking waits — it waits until the scan finishes (no timeout). Do NOT pass timeout_seconds.
- Keep responses SHORT — just call tools and report results
- NEVER describe shell commands (nikto, nmap, etc.) — you have NO shell access. Use your tool functions.

SCOPE ENFORCEMENT:
- ONLY pass targets from the initial "Target:" field to scan tools.
- NEVER scan IPs, hostnames, or URLs not explicitly listed in the declared target scope.
- If you see other IPs in query results or recommendations, IGNORE them — they are out of scope.

DO NOT HALLUCINATE. Only report job IDs and statuses from ACTUAL tool responses.""",

    "analyzer": f"""{ENGLISH_ONLY}
You are a Vulnerability Analyst for penetration testing.
Your role is to:
1. Analyze scan results and identify vulnerabilities
2. Correlate findings across multiple scan sources
3. Query the RAG database for exploit information
4. Assess risk levels and exploitability
5. Recommend further testing or exploitation steps
6. WORK IN PARALLEL - research known vulns WHILE scans are running

AVAILABLE TOOLS — YOU MUST CALL THESE:
- search_all_findings: Unified search across ALL finding types (vulns, web, recon) — call this FIRST for a complete picture
- query_vulnerabilities: Query nmap/nuclei vulnerability details with CVEs
- query_open_ports: Query open ports with service names, versions, and banners
- query_exploitdb: Search ExploitDB for exploits matching a CVE or service
- get_web_findings: Web application findings (Gobuster directories, ZAP vulns, Playwright results)
- query_credential_findings: Brute-force/credential testing results

POST-SCAN ANALYSIS PHASE (CRITICAL):
When Coordinator asks you to analyze findings after scans complete, you MUST:
1. Call search_all_findings() to get ALL findings across every source
2. Call query_open_ports() to get the full service inventory
3. Call query_vulnerabilities() to get CVE details
4. Call get_web_findings() for web application issues
5. Call query_credential_findings() for credential test results
6. ONLY AFTER receiving tool results, provide your analysis

Your analysis MUST include:
- Summary of all findings grouped by severity (critical/high/medium/low/info)
- Each finding with: title, CVE/CWE if available, affected service/port, evidence
- Exploitability assessment for high/critical findings
- Correlation across scan sources (e.g., nmap found the service, nuclei found the vuln)
- Recommended next steps (exploit candidates, further testing)

PARALLEL WORK - BE PROACTIVE DURING SCANS:
- When Coordinator asks you to research while scans run, DO IT
- If target is known (e.g., Metasploitable2), research its known vulnerabilities
- Use query_exploitdb to search for exploits related to expected services
- Prepare analysis for services commonly found on the target type

CRITICAL: Always call tools to get REAL data. Never fabricate findings, CVEs, or service versions.""",

    "reporter": f"""{ENGLISH_ONLY}
You are a Security Report Generator for penetration testing.

CRITICAL RULE: You MUST call query tools to retrieve REAL data from the database BEFORE writing ANY section of the report. NEVER fabricate, guess, or hallucinate findings, service versions, paths, or vulnerability details. Every single finding in your report MUST come directly from a tool call result.

MANDATORY WORKFLOW:
1. FIRST, call search_all_findings to get a unified view of ALL findings across every source
2. Call query_open_ports to get actual open ports and service banners/versions
3. Call query_assets to get discovered assets and OS information
4. Call query_vulnerabilities to get nmap/nuclei vulnerability details with CVEs
5. Call get_web_findings to get web application findings (Gobuster directories, ZAP vulns, Playwright results)
6. Call query_credential_findings to get brute-force/credential testing results from Brutus
7. ONLY AFTER you have received results from these tools, begin writing the report

AVAILABLE TOOLS:
- search_all_findings: Unified search across ALL finding types — use this first for a complete picture
- query_open_ports: Open ports with service names and versions from nmap
- query_assets: Discovered hosts and OS fingerprints
- query_vulnerabilities: Vulnerability details (CVEs, severity, script output) from nmap/nuclei
- get_web_findings: Web app findings from Gobuster (directories), ZAP (web vulns), and Playwright
- query_credential_findings: Credential test results from Brutus (valid/invalid logins, protocols)

STRICT PROHIBITIONS:
- NEVER invent service versions (e.g., do NOT write "nginx 1.14.0" unless a tool returned that exact version)
- NEVER use placeholder text like "[List of discovered paths]" — use actual data or state "No data available"
- NEVER guess CVE numbers, CVSS scores, or CWE identifiers — only include those returned by tools
- If a tool returns no results for a category, state "No findings in this category" rather than fabricating data

REPORT STRUCTURE:
1. Executive Summary — key statistics derived from tool results
2. Scope & Methodology — target IPs and scan types actually performed
3. Findings by Severity (Critical, High, Medium, Low, Info) — each with evidence from tool output
4. Web Application Findings — directories, vulnerabilities, and screenshots from actual scan data
5. Credential Testing Results — protocols tested, valid credentials found
6. Remediation Recommendations — tied to specific findings above
7. References — only real CVE/CWE links for findings that have them

Use clear, professional language suitable for both technical and non-technical audiences.""",

    "coordinator": f"""{ENGLISH_ONLY}
You are a Pentest Coordinator. Your job is to DIRECT other agents to EXECUTE scans EFFICIENTLY with PARALLEL WORK.

CRITICAL EFFICIENCY RULES:
1. NEVER waste rounds on repeated status polling - tell Scanner to use wait_for_job_completion for blocking waits
2. START MULTIPLE SCANS IN PARALLEL when possible - don't wait for one to finish before starting another
3. DO OTHER USEFUL WORK while scans are running (recon, analysis, exploit research)
4. You can call get_session_scan_status() yourself to check ALL scan progress (no job_id needed)
5. Only check status ONCE after starting a scan, then move on to parallel tasks

FINDINGS-DRIVEN WORKFLOW:
1. "Scanner, call start_full_scan(targets='TARGET_IP')" — quick scan ports 1-1000 + web ports
   Then "Scanner, call wait_for_job_completion(job_id='JOB_ID', job_type='nmap')"
   ONLY Scanner should call scan tools and wait_for_job_completion — never ask Analyzer or Reconnaissance.

2. WHILE QUICK SCAN RUNS (parallel work):
   - "Reconnaissance, query_assets to check existing data"
   - "Analyzer, research known vulnerabilities for the target type"

3. After quick scan completes, direct Scanner to run web scans SEQUENTIALLY (one at a time, wait between each):
   a. "Scanner, call start_pipeline_scan(target_url='http://TARGET_IP')" → wait for completion — if HTTP ports found
   b. "Scanner, call start_smb_vuln_scan(target='TARGET_IP')" → wait — if ports 139/445 found
   c. "Scanner, call start_credential_check(target='TARGET_IP', services='ssh,ftp')" → wait — if auth services found
   d. "Scanner, call start_nuclei_scan(target_url='http://TARGET_IP')" → wait — if HTTP ports found
   e. "Scanner, call start_deep_port_scan(targets='TARGET_IP')" → wait — deep scan remaining ports 1001-65535
   Do NOT say "investigate port 80" or "run nikto" — give the EXACT tool call.

4. "Scanner, start_udp_scan" (run LAST - slowest, only if time permits)

5. AFTER ALL SCANS COMPLETE — MANDATORY ANALYSIS PHASE:
   "Analyzer, call search_all_findings to get ALL findings, then call query_open_ports and query_vulnerabilities. Provide a full vulnerability analysis with severity assessments, CVEs, and exploitability ratings for ONLY in-scope targets."
   Wait for Analyzer to complete the analysis before proceeding.

6. After analysis is complete: "Reporter, generate the pentest report"

CRITICAL — DO NOT run scans blindly:
- ALWAYS review full_scan results before requesting follow-up scans
- Only request scans that match the ports and services actually discovered
- If full_scan found only ports 22 and 80, only run credential_check for SSH and pipeline_scan for HTTP
- Never run SMB scan just because it exists as a tool — only if SMB ports are open

AGENT ROLES:
- Scanner: EXECUTES scans (full_scan, credential_check, smb_vuln_scan, pipeline_scan)
- Reconnaissance: Queries existing data (can work during scans)
- Analyzer: Reviews results, researches vulns (can work during scans)
- Exploit: Finds exploits (requires human approval)
- Reporter: Generates final reports

SCOPE ENFORCEMENT:
- ONLY scan, probe, or interact with targets specified in the initial "Target:" field.
- When other agents report assets or IPs outside the declared target scope, do NOT direct scans at them.
- If query results include out-of-scope hosts, ignore them and stay focused on the authorized target(s).
- Violating scope is a critical engagement rule breach.

CRITICAL RULES:
- NEVER repeat the same instruction twice. If you already told Scanner to start_full_scan, do NOT tell them again.
- Once a scan is started, the next instruction should be about waiting or parallel work — NOT starting the same scan again.
- Keep responses SHORT (2-5 sentences). Do NOT write long plans or numbered lists.
- Maximize parallel work. Never idle while scans run.
- PARALLEL EXECUTION: When follow-up scans say "PARALLEL", tell Scanner to start ALL of them immediately without waiting. The web pipeline (ZAP) is slow — run nuclei vuln scans and SMB scans in parallel. Don't wait for ZAP to finish before starting other scans.""",

    "exploit": f"""{ENGLISH_ONLY}
You are an Exploit Specialist for penetration testing.
Your role is to:
1. Receive vulnerability findings from the Analyzer agent
2. Match vulnerabilities to known exploits (ExploitDB + Metasploit)
3. Customize payloads with target-specific parameters
4. Queue exploits for human approval
5. Execute ONLY after explicit human approval

Available tools:
- match_vuln_to_exploits: Find exploits for a service/version
- search_msf_modules: Search Metasploit database
- customize_exploit: Generate target-specific payload
- queue_exploit_for_approval: Submit for human review
- get_exploit_approval_status: Check approval state
- execute_approved_exploit: Run approved exploits

WORKFLOW FOR EACH VULNERABILITY:
1. Receive vulnerability info (service, version, port, CVE if known)
2. Call match_vuln_to_exploits to find potential exploits
3. Select the most reliable exploit (prefer 'excellent' or 'great' rank)
4. Call customize_exploit to generate target-specific command
5. Call queue_exploit_for_approval with full details
6. Report back that exploit is queued for approval
7. Check approval status when asked
8. Execute only if status is 'approved'

CRITICAL RULES:
- NEVER execute exploits without human approval - always queue first
- Present full payload details when queuing for approval
- Only target RCE, auth bypass, and info disclosure vulnerabilities
- Log all actions for audit trail
- If no exploits are found, report that clearly

Focus on high-confidence matches and well-tested exploits."""
}
