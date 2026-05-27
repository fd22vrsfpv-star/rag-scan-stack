"""Param config CRUD + import/export."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

router = APIRouter()


def _get_store():
    from backend.main import store
    return store


class ConfigCreate(BaseModel):
    name: str
    config: dict = {}
    auth_header: Optional[str] = None


class ConfigUpdate(BaseModel):
    name: Optional[str] = None
    config: Optional[dict] = None
    auth_header: Optional[str] = None


@router.get("/api-collections/{cid}/param-configs")
def list_configs(cid: str):
    configs = _get_store().list_configs(cid)
    return {"configs": configs, "total": len(configs)}


@router.post("/api-collections/{cid}/param-configs")
def create_config(cid: str, body: ConfigCreate):
    cfg = _get_store().save_config(cid, body.model_dump())
    return cfg


@router.put("/api-param-configs/{config_id}")
def update_config(config_id: str, body: ConfigUpdate):
    result = _get_store().update_config(config_id, body.model_dump(exclude_none=True))
    if not result:
        raise HTTPException(404, "Config not found")
    return result


@router.delete("/api-param-configs/{config_id}")
def delete_config(config_id: str):
    if not _get_store().delete_config(config_id):
        raise HTTPException(404, "Config not found")
    return {"ok": True}


@router.post("/api-collections/{cid}/param-configs/import")
def import_configs(cid: str, body: dict):
    configs = body.get("configs", [])
    if not configs:
        raise HTTPException(400, "No configs to import")
    imported = _get_store().import_configs(cid, configs)
    return {"ok": True, "imported": len(imported), "configs": imported}
