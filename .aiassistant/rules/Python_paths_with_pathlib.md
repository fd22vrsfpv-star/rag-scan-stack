---
apply: always
---
When editing Python, always use pathlib.Path (not raw strings or os.path.join).
Use Path(__file__).resolve().parents[N] to derive project root and ROOT / "dir" / "file.ext" for joins.

