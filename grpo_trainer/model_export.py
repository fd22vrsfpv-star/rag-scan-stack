"""
Model export pipeline for GRPO-trained models.
Handles LoRA merge, GGUF conversion (for Ollama), and safetensors export (for vLLM).
"""

import json
import logging
import os
import shutil
import subprocess
import uuid
from contextlib import contextmanager
from typing import Dict, Optional

import psycopg2
from psycopg2.extras import Json, RealDictCursor

logger = logging.getLogger(__name__)


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


def merge_lora_adapter(
    base_model_path: str,
    adapter_path: str,
    output_path: str,
) -> str:
    """
    Merge a LoRA adapter into the base model to produce full weights.

    Args:
        base_model_path: Path or HF name of the base model
        adapter_path: Path to the LoRA adapter checkpoint
        output_path: Where to save merged model

    Returns:
        Path to merged model
    """
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    logger.info(f"Loading base model: {base_model_path}")
    tokenizer = AutoTokenizer.from_pretrained(base_model_path)
    model = AutoModelForCausalLM.from_pretrained(
        base_model_path,
        torch_dtype="auto",
        device_map="auto",
    )

    logger.info(f"Loading LoRA adapter: {adapter_path}")
    model = PeftModel.from_pretrained(model, adapter_path)

    logger.info("Merging LoRA weights into base model...")
    model = model.merge_and_unload()

    logger.info(f"Saving merged model to: {output_path}")
    os.makedirs(output_path, exist_ok=True)
    model.save_pretrained(output_path)
    tokenizer.save_pretrained(output_path)

    return output_path


def export_to_gguf(
    merged_model_path: str,
    output_path: str,
    quantization: str = "Q4_K_M",
) -> str:
    """
    Convert merged model to GGUF format for Ollama.

    Args:
        merged_model_path: Path to merged safetensors model
        output_path: Output GGUF file path
        quantization: Quantization method (Q4_K_M, Q5_K_M, Q8_0, etc.)

    Returns:
        Path to GGUF file
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Step 1: Convert to GGUF using llama.cpp's convert script
    convert_script = "/app/llama.cpp/convert_hf_to_gguf.py"
    if not os.path.exists(convert_script):
        raise FileNotFoundError("llama.cpp convert script not found at /app/llama.cpp/convert_hf_to_gguf.py")

    fp16_path = output_path.replace(".gguf", "-f16.gguf")

    # Convert HF to GGUF FP16 (options before positional model arg)
    logger.info(f"Converting to GGUF FP16: {merged_model_path} -> {fp16_path}")
    subprocess.run(
        ["python", convert_script, "--outtype", "f16", "--outfile", fp16_path, merged_model_path],
        check=True,
    )

    # Step 2: Quantize
    quantize_bin = "/app/llama.cpp/llama-quantize"
    if os.path.exists(quantize_bin):
        logger.info(f"Quantizing GGUF: {quantization}")
        subprocess.run(
            [quantize_bin, fp16_path, output_path, quantization],
            check=True,
        )
        os.remove(fp16_path)
    else:
        logger.warning("llama-quantize not found, keeping FP16 GGUF")
        shutil.move(fp16_path, output_path)

    return output_path


def deploy_to_ollama(
    gguf_path: str,
    model_name: str,
    base_model: str = "mistral",
    ollama_url: str = None,
) -> Dict:
    """
    Deploy a GGUF model to Ollama by creating a Modelfile and registering it.

    Args:
        gguf_path: Path to the GGUF model file
        model_name: Name to register in Ollama
        base_model: Base model identifier for the Modelfile FROM line
        ollama_url: Ollama API URL

    Returns:
        Dict with deployment status
    """
    import httpx

    ollama_url = ollama_url or os.environ.get("OLLAMA_URL", "http://ollama:11434")

    # Create Modelfile
    modelfile_content = f"""FROM {gguf_path}

PARAMETER temperature 0.7
PARAMETER top_p 0.9
PARAMETER num_ctx 4096

SYSTEM "You are a specialized penetration testing assistant. Respond in English only."
"""

    logger.info(f"Creating Ollama model: {model_name}")

    response = httpx.post(
        f"{ollama_url}/api/create",
        json={
            "name": model_name,
            "modelfile": modelfile_content,
        },
        timeout=600,
    )

    if response.status_code == 200:
        logger.info(f"Model {model_name} deployed to Ollama successfully")
        return {"status": "success", "model_name": model_name}
    else:
        error = response.text
        logger.error(f"Ollama deployment failed: {error}")
        return {"status": "failed", "error": error}


def export_safetensors(
    merged_model_path: str,
    output_path: str,
) -> str:
    """
    Export merged model as safetensors for vLLM serving.

    Args:
        merged_model_path: Path to merged model
        output_path: Output directory

    Returns:
        Path to safetensors model directory
    """
    if merged_model_path != output_path:
        shutil.copytree(merged_model_path, output_path, dirs_exist_ok=True)
    logger.info(f"Safetensors model ready at: {output_path}")
    return output_path


def register_model(
    model_name: str,
    model_format: str,
    model_path: str,
    base_model: str,
    training_run_id: Optional[uuid.UUID] = None,
    eval_metrics: Optional[Dict] = None,
    is_active: bool = False,
    ab_weight: float = 0.0,
) -> uuid.UUID:
    """
    Register a trained model in the grpo_model_registry.

    Args:
        model_name: Model name
        model_format: gguf, safetensors, or lora
        model_path: Path to model files
        base_model: Base model used for training
        training_run_id: FK to grpo_training_runs
        eval_metrics: Evaluation metrics
        is_active: Whether to activate immediately
        ab_weight: A/B test traffic weight

    Returns:
        Model registry UUID
    """
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO grpo_model_registry
            (model_name, model_format, model_path, base_model,
             training_run_id, eval_metrics, is_active, ab_weight)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (model_name, model_format, model_path, base_model,
             training_run_id, Json(eval_metrics or {}), is_active, ab_weight)
        )
        model_id = cur.fetchone()[0]
        conn.commit()
        return model_id


def full_export_pipeline(
    training_run_id: uuid.UUID,
    base_model_path: str,
    adapter_path: str,
    model_name: str,
    export_gguf: bool = True,
    export_safetensors_flag: bool = False,
    deploy_ollama: bool = True,
    quantization: str = "Q4_K_M",
) -> Dict:
    """
    Run the full export pipeline: merge → convert → deploy → register.

    Args:
        training_run_id: Training run that produced the adapter
        base_model_path: Base model path or HF name
        adapter_path: Path to LoRA adapter
        model_name: Name for the exported model
        export_gguf: Whether to export GGUF
        export_safetensors_flag: Whether to export safetensors
        deploy_ollama: Whether to deploy to Ollama
        quantization: GGUF quantization method

    Returns:
        Dict with export results
    """
    results = {"model_name": model_name, "exports": []}
    output_base = f"/app/checkpoints/{model_name}"

    # Step 1: Merge LoRA
    merged_path = os.path.join(output_base, "merged")
    merge_lora_adapter(base_model_path, adapter_path, merged_path)
    results["merged_path"] = merged_path

    # Step 2: Export formats
    if export_gguf:
        gguf_path = os.path.join(output_base, f"{model_name}-{quantization}.gguf")
        export_to_gguf(merged_path, gguf_path, quantization)
        results["gguf_path"] = gguf_path
        results["exports"].append("gguf")

        # Register GGUF model
        model_id = register_model(
            model_name=f"{model_name}-gguf",
            model_format="gguf",
            model_path=gguf_path,
            base_model=base_model_path,
            training_run_id=training_run_id,
        )
        results["gguf_registry_id"] = str(model_id)

        # Deploy to Ollama
        if deploy_ollama:
            deploy_result = deploy_to_ollama(gguf_path, model_name)
            results["ollama_deploy"] = deploy_result

    if export_safetensors_flag:
        st_path = os.path.join(output_base, "safetensors")
        export_safetensors(merged_path, st_path)
        results["safetensors_path"] = st_path
        results["exports"].append("safetensors")

        model_id = register_model(
            model_name=f"{model_name}-safetensors",
            model_format="safetensors",
            model_path=st_path,
            base_model=base_model_path,
            training_run_id=training_run_id,
        )
        results["safetensors_registry_id"] = str(model_id)

    return results
