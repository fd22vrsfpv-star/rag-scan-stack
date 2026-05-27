"""
Reward functions for GRPO training.
Scores model completions for each task type using human feedback or heuristics.
"""

import re
from typing import List, Optional


def human_feedback_reward(rating: int) -> float:
    """
    Convert a 1-5 human rating to [-1, 1] reward range.

    Args:
        rating: 1-5 human rating

    Returns:
        Normalized reward in [-1, 1]
    """
    return (rating - 3.0) / 2.0


# ========================
# Heuristic reward functions
# ========================

def scan_analysis_reward(completion: str, prompt: str = "") -> float:
    """
    Heuristic reward for scan analysis completions.

    Scores based on:
    - CVE references (+0.2 each, max 0.4)
    - Severity level mentions (+0.15)
    - Remediation advice (+0.15)
    - Proper length (+0.1)
    - No non-English text (-0.3)
    """
    score = 0.0

    # CVE references
    cve_matches = re.findall(r"CVE-\d{4}-\d{4,}", completion)
    score += min(len(cve_matches) * 0.2, 0.4)

    # Severity levels
    severity_terms = ["critical", "high", "medium", "low", "info"]
    if any(term in completion.lower() for term in severity_terms):
        score += 0.15

    # Remediation advice
    remediation_terms = [
        "remediat", "mitigat", "patch", "update", "upgrade",
        "fix", "recommend", "should",
    ]
    if any(term in completion.lower() for term in remediation_terms):
        score += 0.15

    # Proper length (between 100-2000 chars is ideal)
    length = len(completion)
    if 100 <= length <= 2000:
        score += 0.1
    elif length < 50 or length > 5000:
        score -= 0.1

    # Non-English penalty
    if _has_non_english(completion):
        score -= 0.3

    return max(min(score, 1.0), -1.0)


def exploit_recommendation_reward(completion: str, prompt: str = "") -> float:
    """
    Heuristic reward for exploit recommendation completions.

    Scores based on:
    - EDB-ID or MSF module references (+0.25)
    - Metasploit parameters (+0.15)
    - Confidence assessment (+0.1)
    - Proper structure (+0.1)
    """
    score = 0.0

    # EDB-ID or MSF references
    edb_refs = re.findall(r"EDB-\d+|\bexploit/\w+", completion)
    msf_refs = re.findall(r"(exploit|auxiliary|post)/[\w/]+", completion)
    if edb_refs or msf_refs:
        score += 0.25

    # Metasploit parameters
    msf_params = ["RHOST", "RPORT", "LHOST", "LPORT", "PAYLOAD", "TARGET"]
    param_count = sum(1 for p in msf_params if p in completion.upper())
    score += min(param_count * 0.05, 0.15)

    # Confidence assessment
    confidence_terms = ["confidence", "likely", "probable", "certain", "reliable"]
    if any(term in completion.lower() for term in confidence_terms):
        score += 0.1

    # Structured output (has sections or bullet points)
    if re.search(r"^\s*[-*•]", completion, re.MULTILINE):
        score += 0.1

    # Proper length
    length = len(completion)
    if 80 <= length <= 2000:
        score += 0.1
    elif length < 30:
        score -= 0.2

    # Non-English penalty
    if _has_non_english(completion):
        score -= 0.3

    return max(min(score, 1.0), -1.0)


def agent_decision_reward(completion: str, prompt: str = "") -> float:
    """
    Heuristic reward for agent decision/coordination completions.

    Scores based on:
    - Agent name references (+0.2)
    - Tool function name references (+0.2)
    - Directive language (+0.15)
    - Target IP mention (+0.1)
    - Brevity bonus (+0.1 for concise directives)
    """
    score = 0.0

    # Agent name references
    agent_names = ["Scanner", "Analyzer", "Reconnaissance", "Exploit", "Reporter"]
    if any(name in completion for name in agent_names):
        score += 0.2

    # Tool function references
    tool_names = [
        "start_full_scan", "start_masscan", "start_nmap_scan",
        "start_web_scan", "start_nuclei_scan", "start_pipeline_scan",
        "start_credential_check", "start_smb_vuln_scan",
        "query_assets", "query_open_ports", "query_vulnerabilities",
        "query_exploitdb", "wait_for_job_completion",
    ]
    if any(tool in completion for tool in tool_names):
        score += 0.2

    # Directive language
    directive_terms = [
        "please", "run", "scan", "check", "analyze", "execute",
        "start", "investigate", "report",
    ]
    if any(term in completion.lower() for term in directive_terms):
        score += 0.15

    # Target IP
    if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", completion):
        score += 0.1

    # Brevity bonus (coordinators should be concise)
    length = len(completion)
    if 50 <= length <= 500:
        score += 0.1
    elif length > 1500:
        score -= 0.1

    # Non-English penalty
    if _has_non_english(completion):
        score -= 0.3

    return max(min(score, 1.0), -1.0)


def _has_non_english(text: str) -> bool:
    """Check if text contains significant non-English characters."""
    # CJK Unicode ranges
    non_english = len(re.findall(r"[\u4e00-\u9fff\u0e00-\u0e7f\u3040-\u30ff]", text))
    return non_english > 5


# Dispatch table
REWARD_FUNCTIONS = {
    "scan_analysis": scan_analysis_reward,
    "exploit_recommendation": exploit_recommendation_reward,
    "agent_decision": agent_decision_reward,
}


def compute_reward(
    completion: str,
    task_type: str,
    human_rating: Optional[int] = None,
    prompt: str = "",
) -> float:
    """
    Compute reward for a completion.

    Uses human feedback if available, otherwise falls back to heuristics.

    Args:
        completion: Model output text
        task_type: scan_analysis, exploit_recommendation, or agent_decision
        human_rating: Optional 1-5 human rating
        prompt: The input prompt (for context-aware scoring)

    Returns:
        Reward in [-1, 1] range
    """
    if human_rating is not None:
        return human_feedback_reward(human_rating)

    reward_fn = REWARD_FUNCTIONS.get(task_type)
    if reward_fn is None:
        return 0.0
    return reward_fn(completion, prompt)


def batch_reward(
    completions: List[str],
    task_type: str,
    human_ratings: Optional[List[Optional[int]]] = None,
    prompts: Optional[List[str]] = None,
) -> List[float]:
    """
    Compute rewards for a batch of completions.

    Args:
        completions: List of model outputs
        task_type: Task type for all completions
        human_ratings: Optional list of human ratings (None entries use heuristic)
        prompts: Optional list of prompts

    Returns:
        List of rewards in [-1, 1] range
    """
    if human_ratings is None:
        human_ratings = [None] * len(completions)
    if prompts is None:
        prompts = [""] * len(completions)

    return [
        compute_reward(c, task_type, r, p)
        for c, r, p in zip(completions, human_ratings, prompts)
    ]
