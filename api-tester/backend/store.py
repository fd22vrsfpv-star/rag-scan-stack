"""JSON file-based storage layer — replaces Postgres for standalone mode."""

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class JsonStore:
    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        for sub in ("swagger", "collections", "sessions", "history", "configs"):
            (self.data_dir / sub).mkdir(parents=True, exist_ok=True)
        # In-memory index: endpoint_id -> collection_id
        self._ep_index: dict[str, str] = {}
        self._rebuild_index()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _read(self, path: Path) -> dict | list | None:
        if not path.exists():
            return None
        return json.loads(path.read_text())

    def _write(self, path: Path, data):
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, default=str))
        tmp.rename(path)

    def _rebuild_index(self):
        self._ep_index.clear()
        for fp in (self.data_dir / "collections").glob("*.json"):
            try:
                coll = json.loads(fp.read_text())
                cid = coll["id"]
                for ep in coll.get("endpoints", []):
                    self._ep_index[ep["id"]] = cid
            except Exception:
                continue

    # ── Collections ──

    def list_collections(self) -> list[dict]:
        results = []
        for fp in sorted((self.data_dir / "collections").glob("*.json")):
            try:
                coll = json.loads(fp.read_text())
                # Return without full endpoints list for listing
                c = {k: v for k, v in coll.items() if k != "endpoints"}
                c["endpoint_count"] = len(coll.get("endpoints", []))
                results.append(c)
            except Exception:
                continue
        return sorted(results, key=lambda c: c.get("name", ""))

    def get_collection(self, cid: str) -> dict | None:
        path = self.data_dir / "collections" / f"{cid}.json"
        return self._read(path)

    def save_collection(self, data: dict) -> str:
        cid = data.get("id") or str(uuid.uuid4())
        data["id"] = cid
        now = self._now()
        data.setdefault("created_at", now)
        data["updated_at"] = now
        # Assign IDs to endpoints
        for ep in data.get("endpoints", []):
            ep.setdefault("id", str(uuid.uuid4()))
            ep["collection_id"] = cid
            ep.setdefault("created_at", now)
            self._ep_index[ep["id"]] = cid
        data["endpoint_count"] = len(data.get("endpoints", []))
        self._write(self.data_dir / "collections" / f"{cid}.json", data)
        return cid

    def upsert_collection_by_source(self, data: dict) -> str:
        """Find existing collection by source_file and update, or create new."""
        sf = data.get("source_file", "")
        for fp in (self.data_dir / "collections").glob("*.json"):
            try:
                existing = json.loads(fp.read_text())
                if existing.get("source_file") == sf:
                    data["id"] = existing["id"]
                    data["created_at"] = existing.get("created_at", self._now())
                    return self.save_collection(data)
            except Exception:
                continue
        return self.save_collection(data)

    def delete_collection(self, cid: str) -> bool:
        path = self.data_dir / "collections" / f"{cid}.json"
        if not path.exists():
            return False
        coll = self._read(path)
        if coll:
            for ep in coll.get("endpoints", []):
                self._ep_index.pop(ep.get("id", ""), None)
        path.unlink()
        # Cascade: delete configs
        cfg_path = self.data_dir / "configs" / f"{cid}.json"
        if cfg_path.exists():
            cfg_path.unlink()
        return True

    def get_endpoints(self, cid: str, method: str = None, tag: str = None,
                      search: str = None) -> list[dict]:
        coll = self.get_collection(cid)
        if not coll:
            return []
        eps = coll.get("endpoints", [])
        if method:
            eps = [e for e in eps if e["method"].upper() == method.upper()]
        if tag:
            eps = [e for e in eps if tag in (e.get("tags") or [])]
        if search:
            s = search.lower()
            eps = [e for e in eps if s in e.get("path", "").lower()
                   or s in (e.get("summary") or "").lower()
                   or s in (e.get("operation_id") or "").lower()]
        return eps

    def get_endpoint_with_collection(self, eid: str) -> tuple[dict, dict] | None:
        cid = self._ep_index.get(eid)
        if not cid:
            return None
        coll = self.get_collection(cid)
        if not coll:
            return None
        for ep in coll.get("endpoints", []):
            if ep["id"] == eid:
                return ep, coll
        return None

    # ── Sessions ──

    def list_sessions(self) -> list[dict]:
        results = []
        for fp in sorted((self.data_dir / "sessions").glob("*.json"),
                         key=lambda f: f.stat().st_mtime, reverse=True):
            try:
                results.append(json.loads(fp.read_text()))
            except Exception:
                continue
        return results

    def get_session(self, sid: str) -> dict | None:
        return self._read(self.data_dir / "sessions" / f"{sid}.json")

    def save_session(self, data: dict) -> dict:
        sid = data.get("id") or str(uuid.uuid4())
        data["id"] = sid
        now = self._now()
        data.setdefault("created_at", now)
        data["updated_at"] = now
        self._write(self.data_dir / "sessions" / f"{sid}.json", data)
        return data

    def delete_session(self, sid: str) -> bool:
        path = self.data_dir / "sessions" / f"{sid}.json"
        if not path.exists():
            return False
        path.unlink()
        # Also delete history
        hist = self.data_dir / "history" / f"{sid}.json"
        if hist.exists():
            hist.unlink()
        return True

    # ── History ──

    def get_history(self, sid: str, endpoint_id: str = None, limit: int = 50) -> list[dict]:
        data = self._read(self.data_dir / "history" / f"{sid}.json")
        if not data:
            return []
        results = data if isinstance(data, list) else data.get("results", [])
        if endpoint_id:
            results = [r for r in results if r.get("endpoint_id") == endpoint_id]
        return results[:limit]

    def add_result(self, sid: str, result: dict) -> dict:
        result.setdefault("id", str(uuid.uuid4()))
        result.setdefault("created_at", self._now())
        path = self.data_dir / "history" / f"{sid}.json"
        existing = self._read(path)
        results = existing if isinstance(existing, list) else [] if not existing else existing.get("results", [])
        results.insert(0, result)
        results = results[:500]  # cap
        self._write(path, results)
        return result

    def clear_history(self, sid: str) -> int:
        path = self.data_dir / "history" / f"{sid}.json"
        if not path.exists():
            return 0
        data = self._read(path)
        count = len(data) if isinstance(data, list) else len(data.get("results", [])) if data else 0
        self._write(path, [])
        return count

    # ── Param Configs ──

    def list_configs(self, cid: str) -> list[dict]:
        data = self._read(self.data_dir / "configs" / f"{cid}.json")
        if not data:
            return []
        return data.get("configs", []) if isinstance(data, dict) else data

    def save_config(self, cid: str, cfg: dict) -> dict:
        cfg.setdefault("id", str(uuid.uuid4()))
        cfg["collection_id"] = cid
        now = self._now()
        cfg.setdefault("created_at", now)
        cfg["updated_at"] = now
        path = self.data_dir / "configs" / f"{cid}.json"
        data = self._read(path) or {"configs": []}
        if isinstance(data, list):
            data = {"configs": data}
        data["configs"].append(cfg)
        self._write(path, data)
        return cfg

    def update_config(self, config_id: str, updates: dict) -> dict | None:
        for fp in (self.data_dir / "configs").glob("*.json"):
            data = self._read(fp)
            if not data:
                continue
            configs = data.get("configs", []) if isinstance(data, dict) else data
            for cfg in configs:
                if cfg.get("id") == config_id:
                    for k, v in updates.items():
                        if v is not None:
                            cfg[k] = v
                    cfg["updated_at"] = self._now()
                    if isinstance(data, dict):
                        data["configs"] = configs
                    self._write(fp, data if isinstance(data, dict) else {"configs": configs})
                    return cfg
        return None

    def delete_config(self, config_id: str) -> bool:
        for fp in (self.data_dir / "configs").glob("*.json"):
            data = self._read(fp)
            if not data:
                continue
            configs = data.get("configs", []) if isinstance(data, dict) else data
            new_configs = [c for c in configs if c.get("id") != config_id]
            if len(new_configs) < len(configs):
                self._write(fp, {"configs": new_configs})
                return True
        return False

    def import_configs(self, cid: str, configs: list[dict]) -> list[dict]:
        imported = []
        for cfg in configs:
            saved = self.save_config(cid, {
                "name": cfg.get("name", "Imported"),
                "config": cfg.get("config", {}),
                "auth_header": cfg.get("auth_header"),
            })
            imported.append(saved)
        return imported
