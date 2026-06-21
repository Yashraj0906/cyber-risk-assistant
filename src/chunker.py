"""NIST Control Chunker

Takes the 1,016 NIST SP 800-53 controls parsed by data_loader.py and converts them
into chunks suitable for embedding and retrieval.

Strategy: control-aware chunking (NOT naive fixed-size splitting).
Each NIST control becomes its own chunk because controls are self-contained units
of meaning (typically 100-500 words each — perfect chunk size for embedding models).

Each chunk includes the family context prepended so the embedding model understands
what domain the control belongs to (e.g. "Access Control" vs "System Integrity").

Input:  list of dicts from data_loader.fetch_nist_controls()
Output: list of dicts with chunk_text (for embedding) + metadata (for retrieval)
"""
from src.data_loader import fetch_nist_controls


def chunk_nist_controls(controls=None):
    """Convert NIST controls into chunks ready for embedding.

    Each chunk contains:
      - chunk_text: the text that gets embedded (family context + control name + description + guidance)
      - control_id, control_name, family_id, family_name: metadata stored alongside the embedding
    """
    if controls is None:
        controls = fetch_nist_controls()

    chunks = []
    for c in controls:
        description = c.get("description", "").strip()
        guidance = c.get("guidance", "").strip()

        # skip controls with no useful text
        if not description and not guidance:
            continue

        # build the chunk text with family context prepended
        chunk_text = (
            f"NIST 800-53 Control Family: {c['family_name']}. "
            f"Control: {c['control_id']} - {c['control_name']}. "
        )

        if description:
            chunk_text += f"Description: {description} "
        if guidance:
            chunk_text += f"Guidance: {guidance}"

        chunks.append({
            "chunk_text": chunk_text.strip(),
            "control_id": c["control_id"],
            "control_name": c["control_name"],
            "family_id": c["family_id"],
            "family_name": c["family_name"],
            "description": description,
            "guidance": guidance,
        })

    return chunks


if __name__ == "__main__":
    chunks = chunk_nist_controls()
    print(f"Total chunks: {len(chunks)}")
    print(f"\nSample chunk (AC-2):")
    sample = [c for c in chunks if c["control_id"] == "AC-2"][0]
    print(f"  ID: {sample['control_id']}")
    print(f"  Name: {sample['control_name']}")
    print(f"  Text length: {len(sample['chunk_text'])} chars")
    print(f"  Text preview: {sample['chunk_text'][:200]}...")
