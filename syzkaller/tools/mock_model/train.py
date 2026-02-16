"""Training script for the BiGRU syscall sequence model.

Reads syzkaller corpus programs, extracts syscall sequences, and trains
the BiGRU to predict next-syscall given context.
"""

import os
import re
import logging
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader

from model import SyscallBiGRU, Vocabulary

logger = logging.getLogger(__name__)

# Extract syscall name from syzkaller program line (e.g., "open$dir(...)" → "open$dir").
SYSCALL_RE = re.compile(r'^(\w+(?:\$\w+)?)\(')


def parse_corpus_dir(corpus_dir: str) -> list:
    """Parse all programs in a syzkaller corpus directory.

    Returns:
        List of syscall sequences (each is a list of syscall name strings).
    """
    sequences = []
    if not os.path.isdir(corpus_dir):
        logger.warning("Corpus directory not found: %s", corpus_dir)
        return sequences

    for fname in os.listdir(corpus_dir):
        fpath = os.path.join(corpus_dir, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, 'r', errors='replace') as f:
                seq = []
                for line in f:
                    line = line.strip()
                    m = SYSCALL_RE.match(line)
                    if m:
                        seq.append(m.group(1))
                if len(seq) >= 2:
                    sequences.append(seq)
        except Exception as e:
            logger.debug("Skip %s: %s", fname, e)
            continue

    logger.info("Parsed %d sequences from corpus", len(sequences))
    return sequences


class SyscallDataset(Dataset):
    """Dataset of (context, target) pairs from syscall sequences."""

    def __init__(self, sequences: list, vocab: Vocabulary, max_context: int = 20):
        self.samples = []
        for seq in sequences:
            indices = [vocab.encode(s) for s in seq]
            for i in range(1, len(indices)):
                ctx_start = max(0, i - max_context)
                context = indices[ctx_start:i]
                target = indices[i]
                self.samples.append((context, target))

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        return self.samples[idx]


def collate_fn(batch):
    """Pad context sequences to same length."""
    contexts, targets = zip(*batch)
    max_len = max(len(c) for c in contexts)
    padded = torch.zeros(len(contexts), max_len, dtype=torch.long)
    for i, c in enumerate(contexts):
        padded[i, max_len - len(c):] = torch.tensor(c, dtype=torch.long)
    targets = torch.tensor(targets, dtype=torch.long)
    return padded, targets


def train_model(corpus_dir: str, model_path: str = "model.pt",
                vocab_path: str = "vocab.pt",
                epochs: int = 10, batch_size: int = 64,
                lr: float = 0.001, device: str = None) -> dict:
    """Train BiGRU model on corpus data.

    Returns:
        Dict with training stats.
    """
    if device is None:
        device = "cuda" if torch.cuda.is_available() else "cpu"

    # Parse corpus.
    sequences = parse_corpus_dir(corpus_dir)
    if len(sequences) < 10:
        return {"success": False, "message": f"Too few sequences ({len(sequences)})", "samples": 0}

    # Build vocabulary.
    vocab = Vocabulary()
    for seq in sequences:
        for s in seq:
            vocab.add(s)

    logger.info("Vocabulary size: %d", len(vocab))

    # Create dataset.
    dataset = SyscallDataset(sequences, vocab)
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True, collate_fn=collate_fn)

    # Build model.
    model = SyscallBiGRU(vocab_size=len(vocab)).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.CrossEntropyLoss(ignore_index=0)

    # Train.
    model.train()
    total_loss = 0.0
    for epoch in range(epochs):
        epoch_loss = 0.0
        for batch_ctx, batch_target in loader:
            batch_ctx = batch_ctx.to(device)
            batch_target = batch_target.to(device)

            optimizer.zero_grad()
            logits = model(batch_ctx)
            loss = criterion(logits, batch_target)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            epoch_loss += loss.item()

        avg_loss = epoch_loss / max(len(loader), 1)
        total_loss = avg_loss
        if (epoch + 1) % 5 == 0 or epoch == 0:
            logger.info("Epoch %d/%d — loss: %.4f", epoch + 1, epochs, avg_loss)

    # Save model and vocab.
    torch.save(model.state_dict(), model_path)
    torch.save({"word2idx": vocab.word2idx, "idx2word": vocab.idx2word,
                "next_idx": vocab.next_idx}, vocab_path)

    return {
        "success": True,
        "message": f"Trained on {len(dataset)} samples, final loss={total_loss:.4f}",
        "samples": len(dataset),
    }


def incremental_train(training_data_path: str, model_path: str = "model.pt",
                      vocab_path: str = "vocab.pt",
                      epochs: int = 3, batch_size: int = 32,
                      lr: float = 0.0005, device: str = None) -> dict:
    """Incrementally train on collected inference data (Phase 14 D25).

    Args:
        training_data_path: Path to JSONL file with {"context": [...], "predicted": "..."}
        model_path: Checkpoint path to load/save
        vocab_path: Vocabulary path to load/save
        epochs: Number of training epochs
        batch_size: Batch size
        lr: Learning rate (lower for fine-tuning)
        device: Device ("cuda" or "cpu")

    Returns:
        Dict with training stats.
    """
    if device is None:
        device = "cuda" if torch.cuda.is_available() else "cpu"

    # Load existing model and vocab.
    if not os.path.exists(model_path) or not os.path.exists(vocab_path):
        return {"success": False, "message": "No pretrained model found", "samples": 0}

    vocab_data = torch.load(vocab_path, map_location="cpu", weights_only=True)
    vocab = Vocabulary()
    vocab.word2idx = vocab_data["word2idx"]
    vocab.idx2word = {int(k): v for k, v in vocab_data["idx2word"].items()}
    vocab.next_idx = vocab_data["next_idx"]

    model = SyscallBiGRU(vocab_size=len(vocab)).to(device)
    model.load_state_dict(torch.load(model_path, map_location=device, weights_only=True))

    # Parse training data JSONL.
    import json
    sequences = []
    if not os.path.exists(training_data_path):
        return {"success": False, "message": "No training data collected yet", "samples": 0}

    with open(training_data_path, "r") as f:
        for line in f:
            try:
                sample = json.loads(line.strip())
                seq = sample["context"] + [sample["predicted"]]
                sequences.append(seq)
            except Exception:
                continue

    if len(sequences) < 10:
        return {"success": False, "message": f"Too few samples ({len(sequences)})", "samples": 0}

    logger.info("Incremental training on %d samples", len(sequences))

    # Extend vocabulary if needed.
    new_words = 0
    for seq in sequences:
        for s in seq:
            if s not in vocab.word2idx:
                vocab.add(s)
                new_words += 1
    if new_words > 0:
        logger.info("Added %d new words to vocabulary (size=%d)", new_words, len(vocab))
        # Resize model embedding if vocab grew.
        old_size = model.embedding.num_embeddings
        if len(vocab) > old_size:
            new_embedding = nn.Embedding(len(vocab), model.embed_dim, padding_idx=0).to(device)
            with torch.no_grad():
                new_embedding.weight[:old_size] = model.embedding.weight
            model.embedding = new_embedding
            model.fc = nn.Linear(model.hidden_dim * 2, len(vocab)).to(device)

    # Create dataset.
    dataset = SyscallDataset(sequences, vocab)
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True, collate_fn=collate_fn)

    # Fine-tune.
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.CrossEntropyLoss(ignore_index=0)
    model.train()
    total_loss = 0.0

    for epoch in range(epochs):
        epoch_loss = 0.0
        for batch_ctx, batch_target in loader:
            batch_ctx = batch_ctx.to(device)
            batch_target = batch_target.to(device)

            optimizer.zero_grad()
            logits = model(batch_ctx)
            loss = criterion(logits, batch_target)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            epoch_loss += loss.item()

        avg_loss = epoch_loss / max(len(loader), 1)
        total_loss = avg_loss
        logger.info("Epoch %d/%d — loss: %.4f", epoch + 1, epochs, avg_loss)

    # Save updated model and vocab.
    torch.save(model.state_dict(), model_path)
    torch.save({"word2idx": vocab.word2idx, "idx2word": vocab.idx2word,
                "next_idx": vocab.next_idx}, vocab_path)

    # Clear training data file after successful training.
    try:
        os.rename(training_data_path, training_data_path + ".used")
    except Exception:
        pass

    return {
        "success": True,
        "message": f"Incremental training on {len(dataset)} samples, loss={total_loss:.4f}",
        "samples": len(dataset),
    }


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <corpus_dir|training_data.jsonl> [model_path] [vocab_path]")
        print(f"  corpus_dir: Train from scratch on corpus")
        print(f"  training_data.jsonl: Incremental training on collected data")
        sys.exit(1)
    input_path = sys.argv[1]
    model_path = sys.argv[2] if len(sys.argv) > 2 else "model.pt"
    vocab_path = sys.argv[3] if len(sys.argv) > 3 else "vocab.pt"

    if input_path.endswith(".jsonl"):
        result = incremental_train(input_path, model_path, vocab_path)
    else:
        result = train_model(input_path, model_path, vocab_path)
    print(result)
