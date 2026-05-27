# Contributing

## Dev setup
```bash
cp .env.example .env
docker network create agents_net || true
docker compose up -d --build
```

## Style
- Python 3.12, prefer type hints where easy.
- Keep FastAPI endpoints small; push parsing into `etl/`.
- One feature per PR, include a short note in `CHANGELOG.md`.

## Tests (light)
- Lint & compile check run in CI: flake8 + `python -m compileall`.
- Add a small masscan/nmap sample under `samples/` if needed.
