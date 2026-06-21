"""RAG Pipeline — Full Retrieval Orchestrator

This is the core AI module. For each of the top 5 risks, it retrieves the most relevant
NIST SP 800-53 security controls using a multi-stage retrieval pipeline:

Stage 1: Query Augmentation
  - Build a rich query from the risk's vulnerability, asset, and business context
  - More context = better embeddings = better retrieval

Stage 2: Hybrid Search (Dense + Sparse)
  - Dense: BGE embeddings via ChromaDB (catches semantic meaning)
  - Sparse: BM25 keyword matching (catches exact terms)
  - Fused with Reciprocal Rank Fusion (RRF) — combines rank lists without scale issues

Stage 3: Cross-Encoder Reranking
  - Takes the fused top-10 candidates
  - Scores each (query, document) pair with full cross-attention
  - Returns the top-3 most relevant controls

Input:  risk dict from risk_scorer.py
Output: list of top 3 NIST controls with relevance scores
"""
from sentence_transformers import CrossEncoder
from src.vector_store import dense_search, index_nist_controls
from src.sparse_retriever import SparseRetriever
from src.chunker import chunk_nist_controls

RERANKER_MODEL = "cross-encoder/ms-marco-MiniLM-L-6-v2"

_reranker = None
_sparse_retriever = None
_chunks = None
_initialized = False


def initialize():
    """Load models and build indexes. Called once at startup."""
    global _reranker, _sparse_retriever, _chunks, _initialized

    if _initialized:
        return

    print("Initializing RAG pipeline...")

    # load NIST chunks (shared between dense and sparse)
    _chunks = chunk_nist_controls()

    # index into ChromaDB (skips if already done)
    index_nist_controls(_chunks)

    # build BM25 index
    _sparse_retriever = SparseRetriever(_chunks)

    # load cross-encoder reranker
    print("Loading reranker model...")
    _reranker = CrossEncoder(RERANKER_MODEL, max_length=512)

    _initialized = True
    print("RAG pipeline ready.")


def augment_query(risk):
    """Build a rich search query from the risk's context.
    More context = the embedding model has more to work with = better retrieval.
    """
    parts = [
        f"Security control for remediating {risk['vulnerability_name']}",
        f"CVE: {risk['cve']}",
        f"Affected component: {risk['affected_component']}",
        f"Asset type: {risk['asset_type']}",
        f"Business impact: {risk['business_service']} ({risk['revenue_impact']})",
    ]

    if risk.get("threat_actor"):
        parts.append(f"Active threat: {risk['threat_actor']} campaign")
    if risk.get("ransomware_association") == "Yes":
        parts.append("Ransomware associated — high urgency")
    if risk.get("internet_exposed") == "Yes":
        parts.append("Internet-facing asset")

    return ". ".join(parts)


def reciprocal_rank_fusion(dense_results, sparse_results, k=60, top_k=10):
    """Combine dense and sparse result lists using RRF.

    RRF formula: score(d) = sum(1 / (k + rank_i(d))) for each retriever i
    Uses ranks instead of raw scores so it works regardless of score scales.
    """
    doc_scores = {}
    doc_data = {}

    for rank, doc in enumerate(dense_results):
        doc_id = doc["control_id"]
        doc_scores[doc_id] = doc_scores.get(doc_id, 0) + 1 / (k + rank + 1)
        doc_data[doc_id] = doc

    for rank, doc in enumerate(sparse_results):
        doc_id = doc["control_id"]
        doc_scores[doc_id] = doc_scores.get(doc_id, 0) + 1 / (k + rank + 1)
        if doc_id not in doc_data:
            doc_data[doc_id] = doc

    sorted_ids = sorted(doc_scores, key=doc_scores.get, reverse=True)[:top_k]

    return [
        {**doc_data[doc_id], "rrf_score": doc_scores[doc_id]}
        for doc_id in sorted_ids
    ]


def rerank(query, candidates, top_k=3):
    """Score each (query, document) pair with the cross-encoder and return top-k."""
    if not candidates:
        return []

    pairs = [(query, doc["document"]) for doc in candidates]
    scores = _reranker.predict(pairs)

    for doc, score in zip(candidates, scores):
        doc["rerank_score"] = float(score)

    reranked = sorted(candidates, key=lambda x: x["rerank_score"], reverse=True)
    return reranked[:top_k]


def retrieve_nist_guidance(risk):
    """Full pipeline: augment query -> hybrid search -> RRF fusion -> rerank -> return top 3."""
    initialize()

    query = augment_query(risk)

    # dense search via ChromaDB (semantic)
    dense_results = dense_search(query, top_k=10)

    # sparse search via BM25 (keyword)
    sparse_results = _sparse_retriever.search(query, top_k=10)

    # fuse both result lists
    fused = reciprocal_rank_fusion(dense_results, sparse_results, top_k=10)

    # rerank with cross-encoder for precise scoring
    top_controls = rerank(query, fused, top_k=3)

    return top_controls


if __name__ == "__main__":
    from src.data_processor import build_enriched_dataframe
    from src.risk_scorer import get_top_risks

    df = build_enriched_dataframe()
    top5 = get_top_risks(df)

    # test with the #1 risk
    risk = top5[0]
    print(f"Risk: {risk['vulnerability_name']} on {risk['asset_name']}")
    print(f"Augmented query: {augment_query(risk)}\n")

    controls = retrieve_nist_guidance(risk)
    print(f"Retrieved {len(controls)} NIST controls:")
    for i, c in enumerate(controls):
        print(f"\n  {i+1}. {c['control_id']} - {c['control_name']}")
        print(f"     Rerank score: {c['rerank_score']:.4f}")
        print(f"     Text: {c['document'][:150]}...")
