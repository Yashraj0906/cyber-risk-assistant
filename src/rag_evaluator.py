"""RAG Evaluation Module

Measures how well our retrieval pipeline finds the correct NIST controls.
Uses a golden test set (eval/golden_set.json) with 5 queries mapped to expected controls.

Metrics:
  Hit Rate @k: Did the correct primary control appear anywhere in the top-k results?
               (hits / total_queries). Target >= 0.80
  MRR: Mean Reciprocal Rank. How HIGH did the correct control rank?
       (1st = 1.0, 2nd = 0.5, 3rd = 0.33). Target >= 0.70
  Context Precision: Of the retrieved controls, what fraction are actually relevant?
                     (relevant_retrieved / total_retrieved). Target >= 0.60

Also includes a faithfulness checker for LLM output (Phase 4):
  - Checks if NIST control IDs mentioned in LLM text were actually retrieved
  - Catches hallucinated controls

Run this file directly to evaluate the pipeline and save results to eval/eval_results.json.
"""
import os
import json
import re
from datetime import datetime

EVAL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "eval")


def load_golden_set():
    path = os.path.join(EVAL_DIR, "golden_set.json")
    with open(path, "r") as f:
        return json.load(f)


def evaluate_retrieval(retrieve_fn, golden_set=None, k=3):
    """Run the retrieval pipeline on each golden query and compute metrics.

    Args:
        retrieve_fn: function that takes a query string and returns list of result dicts
                     (each must have 'control_id' key)
        golden_set: list of dicts with 'query', 'expected_controls', 'primary_control'
        k: number of results to evaluate
    """
    if golden_set is None:
        golden_set = load_golden_set()

    hit_count = 0
    reciprocal_ranks = []
    precision_scores = []

    for item in golden_set:
        results = retrieve_fn(item["query"], top_k=k)
        retrieved_ids = [r["control_id"] for r in results]
        expected = item["expected_controls"]
        primary = item["primary_control"]

        # hit rate: did the primary control appear in top-k?
        if primary in retrieved_ids:
            hit_count += 1
            rank = retrieved_ids.index(primary) + 1
            reciprocal_ranks.append(1.0 / rank)
        else:
            reciprocal_ranks.append(0.0)

        # context precision: how many retrieved are from the expected set?
        relevant_count = len(set(retrieved_ids) & set(expected))
        precision_scores.append(relevant_count / k if k > 0 else 0)

    return {
        "hit_rate": round(hit_count / len(golden_set), 3),
        "mrr": round(sum(reciprocal_ranks) / len(reciprocal_ranks), 3),
        "context_precision": round(sum(precision_scores) / len(precision_scores), 3),
        "total_queries": len(golden_set),
        "hits": hit_count,
    }


def evaluate_faithfulness(generated_text, retrieved_controls):
    """Check if NIST control IDs in the LLM output were actually retrieved.
    Returns a score 0-1. Score of 1.0 means no hallucinated controls.
    """
    mentioned = set(re.findall(r'[A-Z]{2}-\d+', generated_text))
    retrieved_ids = set()
    for c in retrieved_controls:
        # extract base control ID (e.g. "SI-2" from "SI-2(1)")
        base = re.match(r'[A-Z]{2}-\d+', c.get("control_id", ""))
        if base:
            retrieved_ids.add(base.group())

    if not mentioned:
        return 1.0

    faithful = mentioned & retrieved_ids
    return round(len(faithful) / len(mentioned), 3)


def save_results(metrics, config=None):
    """Save evaluation results to eval/eval_results.json."""
    results = {
        "timestamp": datetime.now().isoformat(),
        "config": config or {},
        "retrieval_metrics": metrics,
    }

    path = os.path.join(EVAL_DIR, "eval_results.json")
    with open(path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"Results saved to {path}")
    return results


if __name__ == "__main__":
    from src.rag_pipeline import initialize, retrieve_nist_guidance

    initialize()

    # wrap retrieve_nist_guidance to accept a plain query string
    def retrieve_fn(query, top_k=3):
        from src.vector_store import dense_search
        from src.sparse_retriever import SparseRetriever
        from src.rag_pipeline import reciprocal_rank_fusion, rerank

        dense_results = dense_search(query, top_k=10)
        sparse = SparseRetriever()
        sparse_results = sparse.search(query, top_k=10)
        fused = reciprocal_rank_fusion(dense_results, sparse_results, top_k=10)
        return rerank(query, fused, top_k=top_k)

    print("Running RAG evaluation on golden set...\n")
    metrics = evaluate_retrieval(retrieve_fn)

    print(f"Hit Rate @3: {metrics['hit_rate']} ({metrics['hits']}/{metrics['total_queries']})")
    print(f"MRR: {metrics['mrr']}")
    print(f"Context Precision: {metrics['context_precision']}")

    save_results(metrics, config={
        "embedding_model": "BAAI/bge-small-en-v1.5",
        "reranker": "cross-encoder/ms-marco-MiniLM-L-6-v2",
        "sparse": "BM25 (rank-bm25)",
        "fusion": "Reciprocal Rank Fusion (k=60)",
        "top_k": 3,
    })
