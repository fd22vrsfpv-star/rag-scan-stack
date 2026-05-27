.PHONY: setup setup-no-start up down logs psql db-reinit db-schema clean

# Unified setup — single command from clone to running stack
setup:
	./scripts/setup.sh

setup-no-start:
	./scripts/setup.sh --no-start

up:
	docker network create agents_net || true
	@# Check if remote DB tunnel is running — if so, skip local postgres
	@if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^rag-db-tunnel$$'; then \
		echo "Remote DB tunnel detected — skipping local postgres + schema (remote DB owns its schema)"; \
		docker compose up -d --build; \
	else \
		COMPOSE_PROFILES=local-db docker compose up -d --build; \
		echo ""; \
		echo "→ Ensuring local DB schema..."; \
		./scripts/ensure_db_schema.sh; \
	fi

down:
	docker compose down

db-status:
	@if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^rag-db-tunnel$$'; then \
		echo "Database mode: REMOTE (SSH tunnel active)"; \
		docker ps --filter name=rag-db-tunnel --format 'table {{.Names}}\t{{.Status}}'; \
	elif docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^rag-postgres$$'; then \
		echo "Database mode: LOCAL (rag-postgres container)"; \
		docker ps --filter name=rag-postgres --format 'table {{.Names}}\t{{.Status}}'; \
	else \
		echo "Database mode: NONE (no database running!)"; \
	fi

db-local:
	@echo "Switching to local database..."
	@docker rm -f rag-db-tunnel 2>/dev/null || true
	docker compose up -d rag-postgres

db-remote:
	@echo "Switching to remote database..."
	curl -sk -X POST https://localhost:3002/api/settings/database/switch/remote

logs:
	docker compose logs -f

psql:
	docker exec -it rag-postgres psql -U $$POSTGRES_USER -d $$POSTGRES_DB

db-schema:
	./scripts/ensure_db_schema.sh

db-reinit:
	# DANGER: destroys DB data
	docker compose down
	docker volume rm rag-scan-stack_rag-pgdata || true
	$(MAKE) up

clean:
	docker compose down -v
