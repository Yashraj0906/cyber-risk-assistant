"""BGE Embedding Module

Uses BAAI/bge-small-en-v1.5 to convert text into 384-dimensional vectors.

Key difference from generic models like MiniLM: BGE uses instruction-prefixed queries.
- Queries get a task instruction prefix ("Represent this sentence for searching...")
- Documents are embedded without any prefix
This asymmetry improves retrieval accuracy because it tells the model
"I'm searching" vs "I'm just encoding a document."

Used by:
  - vector_store.py: to embed NIST control chunks during indexing
  - rag_pipeline.py: to embed the search query at retrieval time
"""
from sentence_transformers import SentenceTransformer

MODEL_NAME = "BAAI/bge-small-en-v1.5"
QUERY_INSTRUCTION = "Represent this sentence for searching relevant security controls: "

_model = None


def _get_model():
    global _model
    if _model is None:
        _model = SentenceTransformer(MODEL_NAME)
    return _model


def embed_query(query):
    """Embed a search query WITH instruction prefix."""
    model = _get_model()
    instructed = QUERY_INSTRUCTION + query
    return model.encode(instructed, normalize_embeddings=True).tolist()


def embed_document(text):
    """Embed a document (NIST control chunk) WITHOUT instruction prefix."""
    model = _get_model()
    return model.encode(text, normalize_embeddings=True).tolist()


def embed_documents_batch(texts, batch_size=64):
    """Batch embed multiple documents for efficient indexing."""
    model = _get_model()
    embeddings = model.encode(texts, normalize_embeddings=True, batch_size=batch_size)
    return embeddings.tolist()


if __name__ == "__main__":
    test_query = "How to remediate a remote code execution vulnerability on a VPN gateway"
    test_doc = "NIST 800-53 Control: SI-2 Flaw Remediation. Organizations identify and correct information system flaws."

    q_emb = embed_query(test_query)
    d_emb = embed_document(test_doc)

    print(f"Model: {MODEL_NAME}")
    print(f"Query embedding dim: {len(q_emb)}")
    print(f"Doc embedding dim: {len(d_emb)}")

    # cosine similarity (both are normalized so dot product = cosine)
    similarity = sum(a * b for a, b in zip(q_emb, d_emb))
    print(f"Cosine similarity: {similarity:.4f}")
