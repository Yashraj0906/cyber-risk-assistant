"""BM25 Sparse Retriever

Keyword-based search over NIST control chunks using BM25 algorithm.
Used alongside dense (BGE) search in our hybrid retrieval pipeline.

BM25 catches exact keyword matches that semantic embeddings might miss.
Example: query mentions "access control" and NIST control is literally named "AC-3 Access Enforcement"
— BM25 catches this directly via keyword matching.

BM25 advantages over TF-IDF:
  - Term frequency saturation (a word appearing 10x doesn't score 10x more)
  - Document length normalization (short and long controls scored fairly)
  - Used by Elasticsearch, Lucene, Solr as their default ranking algorithm

Input:  NIST chunks from chunker.py
Output: ranked list of controls matching the query keywords
"""
import re
from rank_bm25 import BM25Okapi
from src.chunker import chunk_nist_controls


class SparseRetriever:
    def __init__(self, chunks=None):
        if chunks is None:
            chunks = chunk_nist_controls()

        self.chunks = chunks
        self.documents = [c["chunk_text"] for c in chunks]
        self.tokenized_docs = [self._tokenize(doc) for doc in self.documents]
        self.bm25 = BM25Okapi(self.tokenized_docs)

    def _tokenize(self, text):
        return re.findall(r'\w+', text.lower())

    def search(self, query, top_k=10):
        """Search for NIST controls matching query keywords.
        Returns list of dicts with control metadata + bm25_score.
        """
        tokenized_query = self._tokenize(query)
        scores = self.bm25.get_scores(tokenized_query)
        top_indices = scores.argsort()[-top_k:][::-1]

        results = []
        for idx in top_indices:
            if scores[idx] > 0:
                chunk = self.chunks[idx]
                results.append({
                    "control_id": chunk["control_id"],
                    "control_name": chunk["control_name"],
                    "family_name": chunk["family_name"],
                    "document": chunk["chunk_text"],
                    "bm25_score": float(scores[idx]),
                })

        return results


if __name__ == "__main__":
    print("Building BM25 index...")
    retriever = SparseRetriever()
    print(f"Indexed {len(retriever.documents)} documents")

    query = "access control enforcement for remote authentication"
    results = retriever.search(query, top_k=5)
    print(f"\nQuery: {query}")
    for i, r in enumerate(results):
        print(f"  {i+1}. {r['control_id']} - {r['control_name']} (score: {r['bm25_score']:.4f})")
