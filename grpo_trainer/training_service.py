"""
GRPO Training FastAPI Service
Exposes endpoints for training, dataset management, model export, and monitoring.
"""

import json
import logging
import os
import uuid
from contextlib import contextmanager
from datetime import datetime
from typing import Dict, List, Optional

import psycopg2
from psycopg2.extras import Json, RealDictCursor, register_uuid

register_uuid()
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

from grpo_config import GRPOConfig
from data_pipeline import build_dataset

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="GRPO Training Service",
    description="Fine-tune pentest models using Group Relative Policy Optimization",
    version="1.0.0",
)


# ===============================
# Database utilities
# ===============================

def get_db_dsn() -> str:
    return os.environ.get(
        "DB_DSN",
        "postgresql://app:app@rag-postgres:5432/scans"
    )


@contextmanager
def get_db():
    conn = psycopg2.connect(get_db_dsn())
    try:
        yield conn
    finally:
        conn.close()


# ===============================
# Pydantic models
# ===============================

class TrainRequest(BaseModel):
    base_model: str = "mistralai/Mistral-7B-Instruct-v0.3"
    task_types: List[str] = ["scan_analysis", "exploit_recommendation", "agent_decision"]
    dataset_version: Optional[str] = None
    min_rating: int = 1
    config_overrides: Optional[Dict] = None


class DatasetRequest(BaseModel):
    version: str
    task_types: Optional[List[str]] = None
    min_rating: int = 1
    include_synthetic: bool = True


class ExportRequest(BaseModel):
    model_name: str
    export_gguf: bool = True
    export_safetensors: bool = False
    deploy_ollama: bool = True
    quantization: str = "Q4_K_M"


class DeployRequest(BaseModel):
    model_name: str
    is_active: bool = True
    ab_weight: float = 0.0


# ===============================
# Background training runner
# ===============================

def _run_training_background(run_id: uuid.UUID, config: GRPOConfig, dataset_path: str):
    """Run training in background."""
    from train_grpo import run_grpo_training
    run_grpo_training(config, dataset_path, run_id)


# ===============================
# Endpoints
# ===============================

@app.get("/health")
async def health():
    """Health check endpoint."""
    import torch
    return {
        "status": "healthy",
        "cuda_available": torch.cuda.is_available(),
        "cuda_device_count": torch.cuda.device_count() if torch.cuda.is_available() else 0,
    }


@app.get("/gpu")
async def gpu_info():
    """Get GPU information and memory status."""
    import torch

    if not torch.cuda.is_available():
        return {"available": False, "message": "No CUDA GPUs available"}

    gpus = []
    for i in range(torch.cuda.device_count()):
        props = torch.cuda.get_device_properties(i)
        mem = torch.cuda.mem_get_info(i)
        gpus.append({
            "index": i,
            "name": props.name,
            "total_memory_gb": round(props.total_memory / 1e9, 2),
            "free_memory_gb": round(mem[0] / 1e9, 2),
            "used_memory_gb": round((mem[1] - mem[0]) / 1e9, 2),
            "compute_capability": f"{props.major}.{props.minor}",
        })

    return {"available": True, "gpus": gpus}


@app.post("/dataset")
async def create_dataset(request: DatasetRequest):
    """Build a versioned training dataset from DB data."""
    try:
        stats = build_dataset(
            version=request.version,
            task_types=request.task_types,
            min_rating=request.min_rating,
            include_synthetic=request.include_synthetic,
        )
        return {"status": "success", **stats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/train")
async def start_training(request: TrainRequest, background_tasks: BackgroundTasks):
    """
    Start a GRPO training run.
    Training runs in the background. Use GET /train/{id} to check status.
    """
    try:
        # Build config
        config = GRPOConfig(
            base_model=request.base_model,
            task_types=request.task_types,
            min_rating_for_training=request.min_rating,
        )
        if request.config_overrides:
            for key, value in request.config_overrides.items():
                if hasattr(config, key):
                    setattr(config, key, value)

        # Build or locate dataset
        version = request.dataset_version or f"v{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        dataset_path = os.path.join(config.dataset_dir, version, "train.jsonl")

        if not os.path.exists(dataset_path):
            logger.info(f"Building dataset {version}...")
            build_dataset(
                version=version,
                task_types=request.task_types,
                min_rating=request.min_rating,
            )

        if not os.path.exists(dataset_path):
            raise HTTPException(
                status_code=400,
                detail=f"No training data available. Submit feedback first."
            )

        # Create training run record
        from train_grpo import create_training_run
        run_id = create_training_run(config)

        # Start training in background
        background_tasks.add_task(_run_training_background, run_id, config, dataset_path)

        return {
            "run_id": str(run_id),
            "status": "queued",
            "base_model": config.base_model,
            "dataset_version": version,
            "dataset_path": dataset_path,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/train/{run_id}")
async def get_training_status(run_id: str):
    """Get the status and metrics of a training run."""
    try:
        run_uuid = uuid.UUID(run_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid run ID")

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM grpo_training_runs WHERE id = %s",
            (run_uuid,)
        )
        run = cur.fetchone()

    if not run:
        raise HTTPException(status_code=404, detail="Training run not found")

    return {
        "run_id": str(run["id"]),
        "base_model": run["base_model"],
        "dataset_version": run["dataset_version"],
        "task_types": run["task_types"],
        "status": run["status"],
        "hyperparameters": run["hyperparameters"],
        "metrics": run["metrics"],
        "output_path": run["output_path"],
        "error_message": run.get("error_message"),
        "started_at": run["started_at"].isoformat() if run.get("started_at") else None,
        "completed_at": run["completed_at"].isoformat() if run.get("completed_at") else None,
        "created_at": run["created_at"].isoformat() if run.get("created_at") else None,
    }


@app.get("/train")
async def list_training_runs(status: Optional[str] = None, limit: int = 20):
    """List training runs."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        if status:
            cur.execute(
                "SELECT * FROM grpo_training_runs WHERE status = %s ORDER BY created_at DESC LIMIT %s",
                (status, limit)
            )
        else:
            cur.execute(
                "SELECT * FROM grpo_training_runs ORDER BY created_at DESC LIMIT %s",
                (limit,)
            )
        runs = cur.fetchall()

    return [
        {
            "run_id": str(r["id"]),
            "base_model": r["base_model"],
            "status": r["status"],
            "created_at": r["created_at"].isoformat() if r.get("created_at") else None,
        }
        for r in runs
    ]


@app.post("/export/{run_id}")
async def export_model(run_id: str, request: ExportRequest, background_tasks: BackgroundTasks):
    """
    Export a trained model (merge LoRA, convert to GGUF/safetensors, deploy).
    """
    try:
        run_uuid = uuid.UUID(run_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid run ID")

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM grpo_training_runs WHERE id = %s",
            (run_uuid,)
        )
        run = cur.fetchone()

    if not run:
        raise HTTPException(status_code=404, detail="Training run not found")

    if run["status"] != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Training run is not completed (status: {run['status']})"
        )

    adapter_path = run.get("output_path")
    if not adapter_path:
        raise HTTPException(status_code=400, detail="No adapter path found for this run")

    def _run_export():
        from model_export import full_export_pipeline
        full_export_pipeline(
            training_run_id=run_uuid,
            base_model_path=run["base_model"],
            adapter_path=adapter_path,
            model_name=request.model_name,
            export_gguf=request.export_gguf,
            export_safetensors_flag=request.export_safetensors,
            deploy_ollama=request.deploy_ollama,
            quantization=request.quantization,
        )

    background_tasks.add_task(_run_export)

    return {
        "status": "exporting",
        "run_id": run_id,
        "model_name": request.model_name,
        "formats": [
            f for f, enabled in [
                ("gguf", request.export_gguf),
                ("safetensors", request.export_safetensors),
            ] if enabled
        ],
    }


@app.post("/deploy/{model_id}")
async def deploy_model(model_id: str, request: DeployRequest):
    """Activate a model for A/B testing."""
    try:
        model_uuid = uuid.UUID(model_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid model ID")

    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE grpo_model_registry
            SET is_active = %s, ab_weight = %s
            WHERE id = %s
            RETURNING id
            """,
            (request.is_active, request.ab_weight, model_uuid)
        )
        result = cur.fetchone()
        conn.commit()

    if not result:
        raise HTTPException(status_code=404, detail="Model not found in registry")

    return {
        "model_id": model_id,
        "model_name": request.model_name,
        "is_active": request.is_active,
        "ab_weight": request.ab_weight,
    }


@app.get("/models")
async def list_models(active_only: bool = False):
    """List registered models."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        if active_only:
            cur.execute(
                "SELECT * FROM grpo_model_registry WHERE is_active = true ORDER BY created_at DESC"
            )
        else:
            cur.execute(
                "SELECT * FROM grpo_model_registry ORDER BY created_at DESC"
            )
        models = cur.fetchall()

    return [
        {
            "id": str(m["id"]),
            "model_name": m["model_name"],
            "model_format": m["model_format"],
            "model_path": m["model_path"],
            "base_model": m["base_model"],
            "is_active": m["is_active"],
            "ab_weight": float(m["ab_weight"]) if m["ab_weight"] else 0.0,
            "eval_metrics": m["eval_metrics"],
            "created_at": m["created_at"].isoformat() if m.get("created_at") else None,
        }
        for m in models
    ]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8025)
