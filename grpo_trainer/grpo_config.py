"""
GRPO Training Hyperparameter Configuration
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class GRPOConfig:
    """Hyperparameters for GRPO training with QLoRA on 24GB VRAM."""

    # Base model
    base_model: str = "mistralai/Mistral-7B-Instruct-v0.3"
    task_types: List[str] = field(
        default_factory=lambda: ["scan_analysis", "exploit_recommendation", "agent_decision"]
    )

    # QLoRA quantization
    load_in_4bit: bool = True
    bnb_4bit_compute_dtype: str = "bfloat16"
    bnb_4bit_quant_type: str = "nf4"
    bnb_4bit_use_double_quant: bool = True

    # LoRA
    lora_r: int = 16
    lora_alpha: int = 32
    lora_dropout: float = 0.05
    lora_target_modules: List[str] = field(
        default_factory=lambda: [
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ]
    )

    # GRPO
    num_generations: int = 4  # G=4 completions per prompt
    generation_temperature: float = 0.8
    max_completion_length: int = 1024
    max_prompt_length: int = 1024

    # Training
    learning_rate: float = 5e-6
    num_train_epochs: int = 3
    per_device_train_batch_size: int = 1
    gradient_accumulation_steps: int = 8
    gradient_checkpointing: bool = True
    warmup_ratio: float = 0.1
    weight_decay: float = 0.01
    max_grad_norm: float = 1.0
    bf16: bool = True

    # Logging
    logging_steps: int = 10
    save_steps: int = 100
    eval_steps: int = 50
    report_to: str = "wandb"
    wandb_project: str = "rag-scan-grpo"

    # Output
    output_dir: str = "/app/checkpoints"
    dataset_dir: str = "/app/datasets"

    # Reward
    min_rating_for_training: int = 1

    def to_dict(self) -> dict:
        """Convert to dictionary for storage."""
        return {
            "base_model": self.base_model,
            "task_types": self.task_types,
            "load_in_4bit": self.load_in_4bit,
            "lora_r": self.lora_r,
            "lora_alpha": self.lora_alpha,
            "lora_dropout": self.lora_dropout,
            "lora_target_modules": self.lora_target_modules,
            "num_generations": self.num_generations,
            "generation_temperature": self.generation_temperature,
            "max_completion_length": self.max_completion_length,
            "max_prompt_length": self.max_prompt_length,
            "learning_rate": self.learning_rate,
            "num_train_epochs": self.num_train_epochs,
            "per_device_train_batch_size": self.per_device_train_batch_size,
            "gradient_accumulation_steps": self.gradient_accumulation_steps,
            "gradient_checkpointing": self.gradient_checkpointing,
            "bf16": self.bf16,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "GRPOConfig":
        """Create from dictionary."""
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in d.items() if k in valid_fields}
        return cls(**filtered)
