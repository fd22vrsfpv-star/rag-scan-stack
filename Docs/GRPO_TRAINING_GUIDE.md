# GRPO Training Pipeline Guide

Fine-tune pentest models using Group Relative Policy Optimization (GRPO) with human feedback from analyst ratings on agent outputs.

## Overview

The pipeline has three stages:

1. **Feedback Collection** - Capture and rate agent outputs from pentest sessions
2. **GRPO Training** - Fine-tune a model using rated feedback + synthetic scan data
3. **Deployment & A/B Testing** - Export the model and compare it against the baseline

GRPO samples multiple completions per prompt, scores them with a reward function, and uses group-relative advantages to update the policy. No separate critic model is needed, making it memory-efficient for local GPU training.

---

## Prerequisites

- NVIDIA GPU with 12+ GB VRAM (24 GB recommended for 7B models)
- Docker with NVIDIA Container Toolkit
- Running RAG Scan Stack (`docker compose up -d`)
- WandB account (optional, for experiment tracking)

### Hardware Requirements

| Model | VRAM Required | Recommended GPU |
|-------|--------------|-----------------|
| Qwen2.5-3B | ~12 GB | RTX 3080/4070 |
| Mistral-7B | ~18 GB | RTX 3090/4090 |

---

## Quick Start

```bash
# 1. Start the training service
docker compose --profile training up grpo-trainer -d

# 2. Verify it's running
curl http://localhost:8025/health
curl http://localhost:8025/gpu

# 3. Rate some agent outputs (see Feedback Collection below)

# 4. Build a dataset
curl -X POST http://localhost:8025/dataset \
  -H 'Content-Type: application/json' \
  -d '{"version": "v1", "min_rating": 3, "include_synthetic": true}'

# 5. Start training
curl -X POST http://localhost:8025/train \
  -H 'Content-Type: application/json' \
  -d '{"dataset_version": "v1", "min_rating": 3}'

# 6. Monitor progress
curl http://localhost:8025/train
```

---

## Stage 1: Feedback Collection

Feedback endpoints run on the autogen-agents service (port 8015).

### Auto-Capture

Agent outputs are automatically captured as unrated feedback entries when a pentest session completes. Each agent message is classified:

| Agent | Task Type |
|-------|-----------|
| Analyzer | `scan_analysis` |
| Exploit | `exploit_recommendation` |
| Coordinator | `agent_decision` |

You can also manually trigger capture for any session:

```bash
curl -X POST http://localhost:8015/feedback/capture/{session_id}
```

### Submit Feedback Manually

```bash
curl -X POST http://localhost:8015/feedback \
  -H 'Content-Type: application/json' \
  -d '{
    "task_type": "scan_analysis",
    "user_prompt": "Analyze Nmap results for 192.168.1.50",
    "model_response": "Port 22 SSH and 80 HTTP open. Apache 2.4.49 is vulnerable to CVE-2021-41773.",
    "context": {"target_ip": "192.168.1.50"}
  }'
```

### Rate Feedback

```bash
# List unrated entries
curl "http://localhost:8015/feedback?rated=false"

# Rate an entry (1-5 scale)
curl -X PUT http://localhost:8015/feedback/{feedback_id} \
  -H 'Content-Type: application/json' \
  -d '{
    "rating": 4,
    "rating_dimensions": {
      "accuracy": 5,
      "completeness": 4,
      "actionability": 4
    },
    "reviewer_id": "analyst1",
    "notes": "Correctly identified CVE, good remediation advice"
  }'
```

### View Stats

```bash
curl http://localhost:8015/feedback/stats
```

Returns counts by task type, rated/unrated breakdown, average ratings, and rating distribution.

### Export Dataset

```bash
curl "http://localhost:8015/feedback/export?min_rating=3"
```

---

## Stage 2: Training

### Start the Training Service

```bash
docker compose --profile training up grpo-trainer -d
```

The service runs on port 8025. Verify GPU access:

```bash
curl http://localhost:8025/gpu
```

### Build a Dataset

Combines rated human feedback with synthetic prompts extracted from scan data in PostgreSQL:

```bash
curl -X POST http://localhost:8025/dataset \
  -H 'Content-Type: application/json' \
  -d '{
    "version": "v1",
    "task_types": ["scan_analysis", "exploit_recommendation", "agent_decision"],
    "min_rating": 3,
    "include_synthetic": true
  }'
```

**Data sources for synthetic prompts:**
- `scan_analysis` - Joins assets + ports + vulns + web_findings into "analyze these results" prompts
- `exploit_recommendation` - High/critical vulns formatted as "find matching exploit" prompts
- `agent_decision` - Coordinator messages with prior conversation context

### Start a Training Run

```bash
curl -X POST http://localhost:8025/train \
  -H 'Content-Type: application/json' \
  -d '{
    "base_model": "mistralai/Mistral-7B-Instruct-v0.3",
    "task_types": ["scan_analysis", "exploit_recommendation", "agent_decision"],
    "dataset_version": "v1",
    "min_rating": 3
  }'
```

Training runs in the background. The response includes a `run_id` for monitoring.

### Override Hyperparameters

Pass `config_overrides` to tune any parameter:

```bash
curl -X POST http://localhost:8025/train \
  -H 'Content-Type: application/json' \
  -d '{
    "base_model": "Qwen/Qwen2.5-3B-Instruct",
    "dataset_version": "v1",
    "config_overrides": {
      "learning_rate": 1e-5,
      "num_train_epochs": 5,
      "lora_r": 32,
      "lora_alpha": 64,
      "num_generations": 8,
      "generation_temperature": 0.9
    }
  }'
```

### Monitor Training

```bash
# List all runs
curl http://localhost:8025/train

# Check specific run
curl http://localhost:8025/train/{run_id}
```

The status field progresses: `queued` -> `running` -> `completed` (or `failed`).

The `metrics` field contains loss curves, reward values, and training statistics once the run completes.

### Default Hyperparameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `base_model` | Mistral-7B-Instruct-v0.3 | Base model to fine-tune |
| `load_in_4bit` | true | QLoRA 4-bit quantization |
| `bnb_4bit_quant_type` | nf4 | NormalFloat4 quantization |
| `lora_r` | 16 | LoRA rank |
| `lora_alpha` | 32 | LoRA scaling |
| `lora_dropout` | 0.05 | LoRA dropout |
| `num_generations` | 4 | GRPO completions per prompt |
| `generation_temperature` | 0.8 | Sampling temperature |
| `max_completion_length` | 1024 | Max tokens per completion |
| `learning_rate` | 5e-6 | Optimizer learning rate |
| `num_train_epochs` | 3 | Training epochs |
| `gradient_accumulation_steps` | 8 | Effective batch = 1 * 8 = 8 |
| `gradient_checkpointing` | true | Saves VRAM at cost of speed |
| `bf16` | true | BFloat16 training |

### Reward Functions

For prompts **with** human ratings, the 1-5 scale is normalized to [-1, 1].

For prompts **without** ratings, heuristic scoring is used per task type:

**scan_analysis** rewards: CVE references, severity levels, remediation advice, proper length

**exploit_recommendation** rewards: EDB-ID/Metasploit references, MSF parameters (RHOST, LHOST, etc.), confidence assessment

**agent_decision** rewards: agent name references, tool function names, directive language, target IPs, brevity

### WandB Integration

Set your API key to enable experiment tracking:

```bash
# In docker-compose.yml or .env
WANDB_API_KEY=your_key_here
WANDB_PROJECT=rag-scan-grpo
```

---

## Stage 3: Export & Deployment

### Export a Trained Model

After training completes (`status: completed`):

```bash
curl -X POST http://localhost:8025/export/{run_id} \
  -H 'Content-Type: application/json' \
  -d '{
    "model_name": "pentest-7b-v1",
    "export_gguf": true,
    "export_safetensors": false,
    "deploy_ollama": true,
    "quantization": "Q4_K_M"
  }'
```

This will:
1. Merge the LoRA adapter into the base model
2. Convert to GGUF format with Q4_K_M quantization
3. Deploy to Ollama automatically
4. Register in the model registry

**Quantization options:** Q4_K_M (recommended), Q5_K_M (higher quality), Q8_0 (highest quality, largest)

### Verify Deployment

```bash
# Check Ollama has the model
docker exec ollama ollama list

# List registered models
curl http://localhost:8025/models
```

### A/B Testing

Activate a fine-tuned model for A/B testing with a traffic weight:

```bash
# Give the fine-tuned model 50% of traffic
curl -X POST http://localhost:8025/deploy/{model_id} \
  -H 'Content-Type: application/json' \
  -d '{
    "model_name": "pentest-7b-v1",
    "is_active": true,
    "ab_weight": 0.5
  }'
```

Enable A/B testing in the agent stack:

```bash
# Set environment variable for autogen-agents
GRPO_AB_TESTING=true
```

When enabled, each pentest session probabilistically selects between the fine-tuned model and the default model based on `ab_weight`. The selected model is recorded in the session metadata for tracking.

### Measure Improvement

1. Run identical pentest sessions with A/B testing enabled
2. Rate the outputs from both models via the feedback endpoints
3. Compare average ratings:

```bash
# Check stats - compare avg_rating across sessions using different models
curl http://localhost:8015/feedback/stats
```

---

## API Reference

### Training Service (port 8025)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check with CUDA status |
| GET | `/gpu` | GPU info and memory usage |
| POST | `/dataset` | Build versioned training dataset |
| POST | `/train` | Start a GRPO training run |
| GET | `/train` | List training runs |
| GET | `/train/{run_id}` | Get training run status and metrics |
| POST | `/export/{run_id}` | Export and deploy trained model |
| POST | `/deploy/{model_id}` | Activate model for A/B testing |
| GET | `/models` | List registered models |

### Feedback Service (port 8015)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/feedback` | Submit feedback entry |
| GET | `/feedback` | List feedback (filter: task_type, rated, session_id) |
| GET | `/feedback/stats` | Aggregate statistics |
| GET | `/feedback/export` | Export rated dataset as JSONL |
| GET | `/feedback/{id}` | Get single feedback entry |
| PUT | `/feedback/{id}` | Add or update rating |
| POST | `/feedback/capture/{session_id}` | Auto-capture session outputs |

---

## Database Tables

### grpo_feedback
Stores prompt/response pairs with human ratings for training.

| Column | Type | Description |
|--------|------|-------------|
| id | uuid | Primary key |
| task_type | text | scan_analysis, exploit_recommendation, or agent_decision |
| user_prompt | text | The input prompt |
| model_response | text | The model's output |
| rating | int (1-5) | Human quality rating |
| rating_dimensions | jsonb | {accuracy, completeness, actionability} |
| reviewer_id | text | Who rated it |
| session_id | uuid | FK to agent_sessions |
| used_in_training | bool | Whether this entry has been used in a training run |

### grpo_training_runs
Tracks each training run's configuration, status, and results.

| Column | Type | Description |
|--------|------|-------------|
| id | uuid | Primary key |
| base_model | text | Model being fine-tuned |
| dataset_version | text | Version of training dataset |
| task_types | text[] | Which task types were trained |
| hyperparameters | jsonb | Full training config |
| status | text | queued, running, completed, or failed |
| metrics | jsonb | Loss, reward curves, final stats |
| output_path | text | Path to saved LoRA adapter |

### grpo_model_registry
Tracks deployed models and A/B test configuration.

| Column | Type | Description |
|--------|------|-------------|
| id | uuid | Primary key |
| model_name | text | Display name |
| model_format | text | gguf, safetensors, or lora |
| model_path | text | Path to model files |
| is_active | bool | Available for serving |
| ab_weight | numeric | Traffic split (0.0-1.0) |
| training_run_id | uuid | FK to the training run that produced this model |

---

## Troubleshooting

### Training service won't start
```bash
# Check GPU access
docker compose --profile training logs grpo-trainer

# Verify NVIDIA runtime
docker run --rm --gpus all nvidia/cuda:12.1.1-base-ubuntu22.04 nvidia-smi
```

### Out of memory during training
Reduce memory usage with config overrides:
```json
{
  "config_overrides": {
    "per_device_train_batch_size": 1,
    "gradient_accumulation_steps": 16,
    "max_completion_length": 512,
    "num_generations": 2
  }
}
```

Or use a smaller base model:
```json
{
  "base_model": "Qwen/Qwen2.5-3B-Instruct"
}
```

### Empty dataset
Make sure you have either:
- Rated feedback entries (min_rating filter applies)
- Scan data in the database (for synthetic prompts with `include_synthetic: true`)

Check what's available:
```bash
curl http://localhost:8015/feedback/stats
```

### Tables don't exist
If the GRPO tables weren't created during initial DB setup:
```bash
docker exec rag-postgres psql -U app -d scans \
  -f /docker-entrypoint-initdb.d/grpo_migration.sql
```

### Model not appearing in Ollama
Check the export logs and verify Ollama connectivity:
```bash
docker exec ollama ollama list
curl http://localhost:11434/api/tags
```
