"""AXIVON — Cryptographic Integrity module.

Provides:
- sha256_hex()          : deterministic SHA-256 over exact raw text (UTF-8)
- canonical_json()      : stable JSON serialization (sorted keys, compact)
- canonical_hash()      : SHA-256 over the canonical serialization
- merkle_tree()         : build Merkle levels from leaf hashes
- merkle_proof()        : audit path for one leaf
- verify_merkle_proof() : recompute root from leaf + proof

NOTE: this is a Merkle hash tree for tamper-evident batch verification.
It is NOT a blockchain and nothing here should be described as one.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple


def sha256_hex(text: str) -> str:
    """SHA-256 of the exact string, UTF-8 encoded. No normalization is applied."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_json(obj: Any) -> str:
    """Stable serialization used for hashing canonical events."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_hash(obj: Any) -> str:
    """SHA-256 of the canonical JSON serialization of obj."""
    return sha256_hex(canonical_json(obj))


def _h(data: str) -> str:
    return sha256_hex(data)


def merkle_tree(leaf_hashes: List[str]) -> Dict[str, Any]:
    """Build a Merkle tree over the given leaf hashes (in batch order).

    Convention: each leaf is hashed once more (double-hash leaves) before
    being combined, which avoids second-preimage ambiguity between leaves
    and internal nodes. Odd final nodes are duplicated (Bitcoin-style).
    """
    if not leaf_hashes:
        return {"root": _h(""), "levels": [], "leaf_count": 0, "algorithm": "sha256"}

    level: List[str] = [_h(leaf) for leaf in leaf_hashes]
    levels: List[List[str]] = [list(level)]

    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [_h(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        levels.append(list(level))

    return {
        "root": level[0],
        "levels": levels,
        "leaf_count": len(leaf_hashes),
        "algorithm": "sha256",
    }


def merkle_proof(tree: Dict[str, Any], index: int) -> Optional[List[Dict[str, str]]]:
    """Audit path for leaf `index`. Each step: {"hash": ..., "position": "left"|"right"}.

    `position` is the position of the sibling relative to the current node.
    """
    levels = tree.get("levels") or []
    if not levels or index < 0 or index >= len(levels[0]):
        return None

    proof: List[Dict[str, str]] = []
    idx = index
    for depth in range(len(levels) - 1):
        level = levels[depth]
        if idx % 2 == 0:
            sibling = idx + 1
            if sibling >= len(level):
                sibling = idx  # duplicated last node
            proof.append({"hash": level[sibling], "position": "right"})
        else:
            proof.append({"hash": level[idx - 1], "position": "left"})
        idx //= 2
    return proof


def verify_merkle_proof(leaf_hash: str, proof: List[Dict[str, str]], root: str) -> bool:
    """Recompute the root from a leaf hash and its audit path."""
    current = _h(leaf_hash)
    for step in proof or []:
        sibling = step.get("hash", "")
        if step.get("position") == "left":
            current = _h(sibling + current)
        else:
            current = _h(current + sibling)
    return current == root


def verify_leaf_batch(leaf_hashes: List[str], root: str) -> Dict[str, Any]:
    """Rebuild the tree from leaves and check every leaf's proof against root.

    Used by /api/batch and /api/verify-merkle for self-verification.
    """
    tree = merkle_tree(leaf_hashes)
    proofs_ok = True
    for i, leaf in enumerate(leaf_hashes):
        proof = merkle_proof(tree, i)
        if proof is None or not verify_merkle_proof(leaf, proof, tree["root"]):
            proofs_ok = False
            break
    return {
        "root": tree["root"],
        "leaf_count": tree["leaf_count"],
        "algorithm": tree["algorithm"],
        "levels": tree["levels"],
        "verification": {
            "root_rebuilt_matches": tree["root"] == root,
            "all_leaf_proofs_valid": proofs_ok,
            "verified": (tree["root"] == root) and proofs_ok,
            "method": "tree rebuild + per-leaf Merkle proof recheck",
        },
    }


def root_from_leaves(leaf_hashes: List[str]) -> str:
    return merkle_tree(leaf_hashes)["root"]


def tamper_checks_pair(leaves_a: List[str], leaves_b: List[str]) -> Tuple[bool, str, str]:
    """Utility used by tests/docs: two leaf sets that differ must have different roots."""
    root_a = root_from_leaves(leaves_a)
    root_b = root_from_leaves(leaves_b)
    return (root_a != root_b), root_a, root_b
