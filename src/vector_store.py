"""Vector Store Module (ChromaDB)

Stores NIST control embeddings in a persistent ChromaDB collection for dense retrieval.

Indexing (done once):
  NIST chunks from chunker.py -> embedded by embeddings.py -> stored in chroma_db/ folder

Retrieval (done per query):
  Query embedding -> cosine similarity search -> returns top-k most similar controls

The collection is cached on disk (chroma_db/) so we don't re-embed on every app restart.
If the collection already has data, indexing is skipped.
"""
import os
import chromadb
from src.embeddings import embed_documents_batch, embed_query
from src.chunker import chunk_nist_controls

CHROMA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "chroma_db")
COLLECTION_NAME = "nist_controls"

_client = None
_collection = None


def _get_collection():
    global _client, _collection
    if _collection is None:
        _client = chromadb.PersistentClient(path=CHROMA_DIR)
        _collection = _client.get_or_create_collection(
            name=COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"}
        )
    return _collection


def index_nist_controls(chunks=None):
    """Embed and store NIST control chunks in ChromaDB.
    Skips if already indexed.
    """
    collection = _get_collection()

    if collection.count() > 0:
        print(f"ChromaDB already has {collection.count()} controls indexed. Skipping.")
        return collection.count()

    if chunks is None:
        chunks = chunk_nist_controls()

    texts = [c["chunk_text"] for c in chunks]
    ids = [c["control_id"] for c in chunks]
    metadatas = [
        {
            "control_id": c["control_id"],
            "control_name": c["control_name"],
            "family_id": c["family_id"],
            "family_name": c["family_name"],
        }
        for c in chunks
    ]

    print(f"Embedding {len(texts)} NIST controls...")
    embeddings = embed_documents_batch(texts)

    # ChromaDB has a batch limit, add in batches of 500
    batch_size = 500
    for i in range(0, len(texts), batch_size):
        end = min(i + batch_size, len(texts))
        collection.add(
            ids=ids[i:end],
            embeddings=embeddings[i:end],
            documents=texts[i:end],
            metadatas=metadatas[i:end],
        )

    print(f"Indexed {collection.count()} controls in ChromaDB.")
    return collection.count()


def dense_search(query_text, top_k=10):
    """Search ChromaDB for the most similar NIST controls to the query.
    Returns list of dicts with control_id, control_name, family, document text, and distance.
    """
    collection = _get_collection()
    query_embedding = embed_query(query_text)

    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=top_k,
        include=["documents", "metadatas", "distances"],
    )

    output = []
    for i in range(len(results["ids"][0])):
        output.append({
            "control_id": results["metadatas"][0][i]["control_id"],
            "control_name": results["metadatas"][0][i]["control_name"],
            "family_name": results["metadatas"][0][i]["family_name"],
            "document": results["documents"][0][i],
            "distance": results["distances"][0][i],
        })

    return output


if __name__ == "__main__":
    count = index_nist_controls()
    print(f"\nTotal indexed: {count}")

    query = "How to fix a remote code execution vulnerability on a VPN gateway"
    results = dense_search(query, top_k=5)
    print(f"\nQuery: {query}")
    for i, r in enumerate(results):
        print(f"  {i+1}. {r['control_id']} - {r['control_name']} (dist: {r['distance']:.4f})")
