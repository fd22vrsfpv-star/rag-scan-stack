import os
import asyncio
import contextlib
from typing import Tuple

import psycopg2
import pytest
from psycopg2.extras import RealDictCursor

from utils.followup_engine import ensure_followup_schema, enqueue_followups_from_ports
from utils.task_worker import DBQueueWorker


TEST_DB_DSN = os.environ.get("TEST_DB_DSN", os.environ.get("DB_DSN", "postgresql://app:app@127.0.0.1:5432/scans"))


def _conn():
    return psycopg2.connect(TEST_DB_DSN)


def _ensure_core_tables():
    with _conn() as conn, conn.cursor() as cur:
        cur.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                ip inet NOT NULL,
                first_seen timestamptz DEFAULT now(),
                last_seen timestamptz DEFAULT now()
            )""")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS ports (
                id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                asset_id uuid REFERENCES assets(id) ON DELETE CASCADE,
                proto text,
                port integer,
                service text,
                product text,
                version text,
                banner text,
                is_open boolean DEFAULT true,
                first_seen timestamptz DEFAULT now(),
                last_seen timestamptz DEFAULT now()
            )""")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                type text NOT NULL,
                status text NOT NULL DEFAULT 'queued',
                params jsonb NOT NULL DEFAULT '{}'::jsonb,
                total_tasks integer NOT NULL DEFAULT 0,
                finished_tasks integer NOT NULL DEFAULT 0,
                error text,
                created_at timestamptz NOT NULL DEFAULT now(),
                started_at timestamptz,
                finished_at timestamptz
            )""")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                job_id uuid REFERENCES jobs(id) ON DELETE CASCADE,
                type text NOT NULL,
                target_host inet,
                target_port integer,
                proto text,
                action text,
                status text NOT NULL DEFAULT 'queued',
                attempt integer NOT NULL DEFAULT 0,
                last_error text,
                created_at timestamptz NOT NULL DEFAULT now(),
                started_at timestamptz,
                finished_at timestamptz
            )""")
        conn.commit()


def _seed_asset_port(ip: str, port: int, service: str, product: str = None, banner: str = None):
    with _conn() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("INSERT INTO assets (ip) VALUES (%s::inet) RETURNING id", (ip,))
        aid = cur.fetchone()["id"]
        cur.execute(
            """INSERT INTO ports (asset_id, proto, port, service, product, banner, is_open)
               VALUES (%s, 'tcp', %s, %s, %s, %s, true)""",
            (aid, port, service, product, banner),
        )
        conn.commit()


@contextlib.asynccontextmanager
async def _start_http_server() -> Tuple[str, int]:
    host = "127.0.0.1"

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        _ = await reader.read(1024)
        body = b"<html><head><title>Test Service</title></head><body>Hello</body></html>"
        resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        writer.write(resp)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, host=host, port=0)
    addr = server.sockets[0].getsockname()
    try:
        yield host, addr[1]
    finally:
        server.close()
        await server.wait_closed()


@contextlib.asynccontextmanager
async def _start_ssh_like_server() -> Tuple[str, int]:
    host = "127.0.0.1"

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        writer.write(b"SSH-2.0-OpenSSH_9.0\r\n")
        await writer.drain()
        await asyncio.sleep(0.1)
        writer.close()

    server = await asyncio.start_server(handle, host=host, port=0)
    addr = server.sockets[0].getsockname()
    try:
        yield host, addr[1]
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_adaptive_followups_end_to_end():
    _ensure_core_tables()
    ensure_followup_schema()

    async with _start_http_server() as (hhost, hport), _start_ssh_like_server() as (shost, sport):
        _seed_asset_port(hhost, hport, service="http", product="test-http")
        _seed_asset_port(shost, sport, service="ssh", product="OpenSSH")

        enq = enqueue_followups_from_ports(job_id=None)
        assert enq["enqueued"] >= 2

        worker = DBQueueWorker(db_dsn=TEST_DB_DSN, claim_batch=10)
        stats = await worker.run_until_idle()
        assert stats["ok"] >= 2

        with _conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM followup_findings")
            count = cur.fetchone()[0]
            assert count >= 2
