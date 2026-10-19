// Exploit-research "compare models" selection (1-3 LLMs run against the SAME
// research prompt, compared at a post-review step).
//
// This is a BROWSER-LOCAL preference, not stack config: it lives in
// localStorage, so it does not follow the operator to another browser, another
// machine, or another operator on the same dashboard. There is deliberately no
// server-side default -- a pick that silently changed which models every
// operator's research ran through would be a stack-wide cost change made from
// one person's browser.
//
// Two surfaces read and write it (Settings -> LLM Tuning, and the Exploit
// Workbench's inline chip row). They share this module so the key, the cap and
// the fail-soft behaviour cannot drift between them.

export const RESEARCH_MODELS_KEY = 'workbench.researchModels'

/** Max models a single research fanout may use (rag-api caps at 3 as well). */
export const RESEARCH_MODELS_MAX = 3

/** Picked models, or [] when unset/unreadable. Never throws: a private window
 *  with no storage must not break the page. */
export function readResearchModels(): string[] {
  try {
    const raw = JSON.parse(localStorage.getItem(RESEARCH_MODELS_KEY) || '[]')
    if (!Array.isArray(raw)) return []
    return raw.filter((m): m is string => typeof m === 'string' && !!m.trim())
               .slice(0, RESEARCH_MODELS_MAX)
  } catch {
    return []
  }
}

/** Persist the selection. Never throws (see above). */
export function writeResearchModels(models: string[]): void {
  try {
    localStorage.setItem(RESEARCH_MODELS_KEY,
      JSON.stringify(models.slice(0, RESEARCH_MODELS_MAX)))
  } catch {
    /* fail-soft */
  }
}
