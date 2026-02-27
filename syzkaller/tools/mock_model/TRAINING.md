# MOCK BiGRU Training Pipeline

Phase 14 D25: Enhanced training pipeline with inference data collection and incremental training.

## Features

### 1. Training Data Collection
The server automatically logs inference samples for future training:
- **Sampling rate**: 1 in 100 predictions (configurable)
- **Output**: `training_data.jsonl` (JSONL format)
- **Format**: `{"context": ["syscall1", "syscall2", ...], "predicted": "syscall3"}`

### 2. Initial Training (from corpus)
Train a new model from scratch using syzkaller corpus programs:

```bash
python3 train.py /path/to/corpus/dir model.pt vocab.pt
```

This:
- Parses all corpus programs
- Builds vocabulary from syscall names
- Trains BiGRU model (10 epochs)
- Saves model checkpoint and vocabulary

### 3. Incremental Training (from collected data)
Fine-tune the model on collected inference data:

```bash
python3 train.py training_data.jsonl model.pt vocab.pt
```

This:
- Loads existing model and vocabulary
- Extends vocabulary with new syscalls if needed
- Fine-tunes on collected samples (3 epochs, lower learning rate)
- Archives used training data to `training_data.jsonl.used`

### 4. Model Checkpoints
The server automatically loads the latest checkpoint on startup:
- **Model**: `model.pt` (PyTorch state dict)
- **Vocabulary**: `vocab.pt` (word2idx, idx2word mappings)

## Workflow

1. **Initial Setup**: Train from corpus once to bootstrap the model
2. **Deployment**: Start server, it begins collecting inference samples
3. **Periodic Retraining**: Run incremental training every N hours/days
4. **Reload**: Server auto-reloads on retrain RPC (no restart needed)

## Configuration

In `server.py`:
- `collect_training_data = True` — enable/disable collection
- `inference_count % 100 == 0` — sampling rate (1/100)
- `request.calls[-20:]` — max context window (20 syscalls)

In `train.py`:
- `epochs=10` — full training epochs
- `epochs=3` — incremental training epochs
- `lr=0.001` — full training learning rate
- `lr=0.0005` — incremental training learning rate (lower for stability)

## Automatic Vocabulary Expansion

When incremental training encounters new syscalls:
- Vocabulary is extended automatically
- Model embedding layer is resized
- New embeddings initialized randomly
- Old embeddings preserved

This allows the model to adapt to new syscall types discovered by the fuzzer.
