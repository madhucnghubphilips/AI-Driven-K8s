from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


ROOT_DIR = Path(__file__).resolve().parent
KNOWLEDGE_DIR = ROOT_DIR / "knowledge_base"
VECTOR_DIR = ROOT_DIR / "vector_store"


def clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def chunk_text(text: str, chunk_size: int = 1200, overlap: int = 180) -> list[str]:
    text = clean_text(text)
    if not text:
        return []
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(start + chunk_size, len(text))
        chunks.append(text[start:end])
        if end == len(text):
            break
        start = max(0, end - overlap)
    return chunks


def load_markdown_chunks() -> list[dict[str, Any]]:
    chunks: list[dict[str, Any]] = []
    for path in sorted(KNOWLEDGE_DIR.rglob("*.md")):
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = str(path.relative_to(ROOT_DIR)).replace("\\", "/")
        for index, chunk in enumerate(chunk_text(text)):
            digest = hashlib.sha256(f"{rel}:{index}:{chunk}".encode("utf-8")).hexdigest()
            chunks.append(
                {
                    "id": digest,
                    "source": rel,
                    "chunk_index": index,
                    "text": chunk,
                }
            )
    return chunks


def write_keyword_metadata(chunks: list[dict[str, Any]]) -> None:
    VECTOR_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "backend": "keyword",
        "chunk_count": len(chunks),
        "chunks": chunks,
    }
    (VECTOR_DIR / "metadata.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


def try_write_faiss(chunks: list[dict[str, Any]], model_name: str) -> bool:
    try:
        import faiss
        import numpy as np
        from sentence_transformers import SentenceTransformer
    except Exception:
        return False

    if not chunks:
        return False

    encoder = SentenceTransformer(model_name)
    embeddings = encoder.encode([chunk["text"] for chunk in chunks], normalize_embeddings=True)
    vectors = np.asarray(embeddings, dtype="float32")
    index = faiss.IndexFlatIP(vectors.shape[1])
    index.add(vectors)
    faiss.write_index(index, str(VECTOR_DIR / "faiss.index"))

    payload = {
        "version": 1,
        "backend": "faiss",
        "embedding_model": model_name,
        "chunk_count": len(chunks),
        "chunks": chunks,
    }
    (VECTOR_DIR / "metadata.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest KubeSentinel Markdown knowledge files.")
    parser.add_argument("--model", default="sentence-transformers/all-MiniLM-L6-v2", help="SentenceTransformer model for optional FAISS index.")
    parser.add_argument("--keyword-only", action="store_true", help="Only write metadata.json and skip FAISS.")
    args = parser.parse_args()

    KNOWLEDGE_DIR.mkdir(parents=True, exist_ok=True)
    VECTOR_DIR.mkdir(parents=True, exist_ok=True)

    chunks = load_markdown_chunks()
    write_keyword_metadata(chunks)
    backend = "keyword"
    if not args.keyword_only and try_write_faiss(chunks, args.model):
        backend = "faiss"

    print(f"Ingested {len(chunks)} chunks into vector_store using {backend} backend.")


if __name__ == "__main__":
    main()
