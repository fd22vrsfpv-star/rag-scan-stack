---
apply: always
---
# Global AI Rules for This Repo

**Canonical project root:** `/utils/agents`. Treat all relative paths as under this root.

## General
- Never output placeholder paths like `path/to`, `<project_root>`, `<path>`, or `C:\path\to`.
- If unsure of a real path, ask for it rather than inventing placeholders.

## Python
- Always use `pathlib.Path` (not raw strings or `os.path.join`).
- Prefer our helpers:
  ```python
  from utils.path_utils import ROOT, resources, data_dir, ensure_parent

- “Do not create /utils/agents/llm_query.py.”
- “If a module exists both as a file and a package, use the package.”

#Never output placeholder paths or tokens: "path/to", "path\to", "<project_root>", "<path>", "C:\path\to".
- If unsure of a real path, ask—do not invent placeholders.
- Do not emit any line starting with "to\" in generated code or YAML.

