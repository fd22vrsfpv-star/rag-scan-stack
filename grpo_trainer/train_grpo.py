"""
Core GRPO training loop using TRL GRPOTrainer with QLoRA.
"""

import json
import logging
import os
import uuid
from contextlib import contextmanager
from datetime import datetime
from typing import Dict, List, Optional

import torch
from datasets import Dataset
from psycopg2.extras import Json, register_uuid

register_uuid()

from grpo_config import GRPOConfig
from reward_functions import compute_reward

logger = logging.getLogger(__name__)


def get_db_dsn() -> str:
    return os.environ.get(
        "DB_DSN",
        "postgresql://app:app@rag-postgres:5432/scans"
    )


@contextmanager
def get_db():
    import psycopg2
    conn = psycopg2.connect(get_db_dsn())
    try:
        yield conn
    finally:
        conn.close()


def create_training_run(config: GRPOConfig) -> uuid.UUID:
    """Record a new training run in the database."""
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO grpo_training_runs
            (base_model, dataset_version, task_types, hyperparameters, status)
            VALUES (%s, %s, %s, %s, 'queued')
            RETURNING id
            """,
            (config.base_model, "latest", config.task_types,
             Json(config.to_dict()))
        )
        run_id = cur.fetchone()[0]
        conn.commit()
        return run_id


def update_training_run(
    run_id: uuid.UUID,
    status: Optional[str] = None,
    metrics: Optional[Dict] = None,
    output_path: Optional[str] = None,
    error_message: Optional[str] = None,
):
    """Update training run status and metrics."""
    with get_db() as conn, conn.cursor() as cur:
        updates = []
        params = []

        if status:
            updates.append("status = %s")
            params.append(status)
            if status == "running":
                updates.append("started_at = NOW()")
            elif status in ("completed", "failed"):
                updates.append("completed_at = NOW()")

        if metrics:
            updates.append("metrics = %s")
            params.append(Json(metrics))

        if output_path:
            updates.append("output_path = %s")
            params.append(output_path)

        if error_message:
            updates.append("error_message = %s")
            params.append(error_message)

        if updates:
            sql = f"UPDATE grpo_training_runs SET {', '.join(updates)} WHERE id = %s"
            params.append(run_id)
            cur.execute(sql, params)
            conn.commit()


def load_training_data(dataset_path: str) -> Dataset:
    """
    Load JSONL training data into a HuggingFace Dataset.

    Args:
        dataset_path: Path to train.jsonl

    Returns:
        HuggingFace Dataset with 'prompt' column
    """
    entries = []
    with open(dataset_path) as f:
        for line in f:
            entry = json.loads(line.strip())
            entries.append(entry)

    # Format for GRPOTrainer: needs 'prompt' column
    formatted = []
    for entry in entries:
        prompt_text = entry.get("prompt", "")
        formatted.append({
            "prompt": prompt_text,
            "task_type": entry.get("task_type", "scan_analysis"),
            "human_rating": entry.get("rating"),
        })

    return Dataset.from_list(formatted)


def build_reward_function(task_types: List[str]):
    """
    Build a reward function compatible with TRL GRPOTrainer.

    The reward function receives completions and returns rewards.
    """
    def reward_fn(completions: list, **kwargs) -> list:
        """
        Compute rewards for a batch of completions.

        Args:
            completions: List of completion strings

        Returns:
            List of reward floats
        """
        rewards = []
        for completion in completions:
            # Extract text from completion
            if isinstance(completion, list):
                # Tokenized format - join tokens
                text = " ".join(str(t) for t in completion)
            else:
                text = str(completion)

            # Use first task_type as default (GRPO samples from same prompt)
            task_type = task_types[0] if task_types else "scan_analysis"
            reward = compute_reward(text, task_type)
            rewards.append(reward)

        return rewards

    return reward_fn


def run_grpo_training(
    config: GRPOConfig,
    dataset_path: str,
    run_id: Optional[uuid.UUID] = None,
) -> Dict:
    """
    Execute GRPO training with QLoRA.

    Args:
        config: Training configuration
        dataset_path: Path to JSONL training data
        run_id: Optional training run ID (creates one if not provided)

    Returns:
        Dict with training results
    """
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from trl import GRPOConfig as TRLGRPOConfig, GRPOTrainer

    if run_id is None:
        run_id = create_training_run(config)

    update_training_run(run_id, status="running")
    logger.info(f"Starting GRPO training run {run_id}")

    try:
        # Load dataset
        logger.info(f"Loading dataset from {dataset_path}")
        dataset = load_training_data(dataset_path)
        logger.info(f"Dataset size: {len(dataset)} entries")

        # QLoRA quantization config
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=config.load_in_4bit,
            bnb_4bit_compute_dtype=getattr(torch, config.bnb_4bit_compute_dtype),
            bnb_4bit_quant_type=config.bnb_4bit_quant_type,
            bnb_4bit_use_double_quant=config.bnb_4bit_use_double_quant,
        )

        # Load model
        logger.info(f"Loading base model: {config.base_model}")
        model = AutoModelForCausalLM.from_pretrained(
            config.base_model,
            quantization_config=bnb_config,
            device_map="auto",
            torch_dtype=torch.bfloat16,
        )
        tokenizer = AutoTokenizer.from_pretrained(config.base_model)

        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token

        # Prepare for QLoRA
        model = prepare_model_for_kbit_training(model)

        # LoRA config
        lora_config = LoraConfig(
            r=config.lora_r,
            lora_alpha=config.lora_alpha,
            lora_dropout=config.lora_dropout,
            target_modules=config.lora_target_modules,
            bias="none",
            task_type="CAUSAL_LM",
        )

        # Build reward function
        reward_fn = build_reward_function(config.task_types)

        # Output directory
        output_dir = os.path.join(config.output_dir, str(run_id))
        os.makedirs(output_dir, exist_ok=True)

        # TRL GRPO training config
        training_config = TRLGRPOConfig(
            output_dir=output_dir,
            num_train_epochs=config.num_train_epochs,
            per_device_train_batch_size=config.per_device_train_batch_size,
            gradient_accumulation_steps=config.gradient_accumulation_steps,
            gradient_checkpointing=config.gradient_checkpointing,
            learning_rate=config.learning_rate,
            warmup_ratio=config.warmup_ratio,
            weight_decay=config.weight_decay,
            max_grad_norm=config.max_grad_norm,
            bf16=config.bf16,
            logging_steps=config.logging_steps,
            save_steps=config.save_steps,
            num_generations=config.num_generations,
            max_completion_length=config.max_completion_length,
            report_to=config.report_to if os.environ.get("WANDB_API_KEY") else "none",
        )

        # Create trainer
        logger.info("Creating GRPOTrainer...")
        trainer = GRPOTrainer(
            model=model,
            args=training_config,
            train_dataset=dataset,
            processing_class=tokenizer,
            reward_funcs=reward_fn,
            peft_config=lora_config,
        )

        # Train
        logger.info("Starting training...")
        train_result = trainer.train()

        # Save final adapter
        final_adapter_path = os.path.join(output_dir, "final_adapter")
        trainer.save_model(final_adapter_path)
        tokenizer.save_pretrained(final_adapter_path)

        # Collect metrics
        metrics = {
            "train_loss": train_result.training_loss,
            "train_runtime": train_result.metrics.get("train_runtime"),
            "train_samples_per_second": train_result.metrics.get("train_samples_per_second"),
            "total_steps": train_result.global_step,
            "adapter_path": final_adapter_path,
        }

        update_training_run(
            run_id,
            status="completed",
            metrics=metrics,
            output_path=final_adapter_path,
        )

        logger.info(f"Training completed. Loss: {train_result.training_loss:.4f}")
        return {
            "run_id": str(run_id),
            "status": "completed",
            "metrics": metrics,
            "adapter_path": final_adapter_path,
        }

    except Exception as e:
        logger.error(f"Training failed: {e}", exc_info=True)
        update_training_run(run_id, status="failed", error_message=str(e))
        return {
            "run_id": str(run_id),
            "status": "failed",
            "error": str(e),
        }
