# ============================================================
# BLIP ENDPOINT SENTINEL — core/rag_engine.py
# Local RAG Engine — ChromaDB + sentence-transformers
# Indexes company policies and semantically matches
# clipboard content against them.
# 100% local, no cloud required, anonymized_telemetry=False
# ============================================================

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer


# ── RAG Match result ──────────────────────────────────────────

@dataclass
class RAGMatch:
    policy_id:    str
    rule_id:      str
    description:  str
    distance:     float       # 0.0 = exact match, 1.0 = no match
    group:        str
    severity:     str
    chunk:        str         # the policy chunk that was matched


@dataclass
class RAGResult:
    is_violation:    bool
    matches:         list[RAGMatch] = field(default_factory=list)
    best_distance:   float = 1.0
    query_time_ms:   float = 0.0

    @property
    def best_match(self) -> Optional[RAGMatch]:
        if not self.matches:
            return None
        return min(self.matches, key=lambda m: m.distance)

    @property
    def violated_policies(self) -> list[str]:
        return list({m.policy_id for m in self.matches})


# ── Policy chunk builder ──────────────────────────────────────

def _build_chunks(policy: dict) -> list[dict]:
    """
    Break a policy JSON into indexable chunks.
    Each chunk = one rule + policy metadata.
    Returns list of dicts with 'text', 'metadata', 'chunk_id'.
    """
    chunks = []
    policy_id = policy.get("policy_id", "UNKNOWN")
    group     = policy.get("group", "general")
    severity  = policy.get("severity", "MEDIUM")
    desc      = policy.get("description", "")

    for rule in policy.get("rules", []):
        rule_id    = rule.get("rule_id", "R-000")
        rule_desc  = rule.get("description", "")
        keywords   = rule.get("keywords", [])

        # Build a rich text chunk for embedding
        chunk_text = (
            f"Policy: {desc}. "
            f"Rule {rule_id}: {rule_desc}. "
            f"Keywords: {', '.join(keywords)}."
        )

        chunks.append({
            "chunk_id": f"{policy_id}_{rule_id}",
            "text":     chunk_text,
            "metadata": {
                "policy_id": policy_id,
                "rule_id":   rule_id,
                "group":     group,
                "severity":  severity,
                "description": rule_desc,
                "chunk_text": chunk_text[:200],
            }
        })

    return chunks


# ── RAG Engine ────────────────────────────────────────────────

class RAGEngine:
    """
    Local ChromaDB-backed semantic policy engine.

    Flow:
      1. Load all policy JSON files from policies/ dir
      2. Embed each rule chunk with all-MiniLM-L6-v2
      3. Store in persistent ChromaDB collection
      4. At scan time: embed clipboard text, query top-K,
         flag POLICY VIOLATION if distance < threshold
    """

    def __init__(
        self,
        policies_dir:   str  = "./config/policies",
        chroma_dir:     str  = "./data/chroma_db",
        collection_name: str = "company_policies",
        model_name:     str  = "all-MiniLM-L6-v2",
        distance_threshold: float = 0.45,
        top_k:          int  = 3,
    ):
        self._policies_dir        = Path(policies_dir)
        self._chroma_dir          = chroma_dir
        self._collection_name     = collection_name
        self._model_name          = model_name
        self._distance_threshold  = distance_threshold
        self._top_k               = top_k

        self._model:      Optional[SentenceTransformer] = None
        self._client:     Optional[chromadb.Client]     = None
        self._collection: Optional[chromadb.Collection] = None
        self._ready       = False

    # ── Initialisation ────────────────────────────────────────

    def initialize(self) -> bool:
        """
        Load model + ChromaDB. Index policies if not already done.
        Call once at daemon startup — takes ~3–5s first time.
        Returns True if ready.
        """
        try:
            print("[RAG] Loading embedding model...")
            t0 = time.perf_counter()
            self._model = SentenceTransformer(self._model_name)
            print(f"[RAG] Model loaded in {(time.perf_counter()-t0)*1000:.0f}ms")

            print("[RAG] Connecting to ChromaDB...")
            os.makedirs(self._chroma_dir, exist_ok=True)
            self._client = chromadb.PersistentClient(
                path=self._chroma_dir,
                settings=Settings(anonymized_telemetry=False)
            )

            # Get or create collection
            self._collection = self._client.get_or_create_collection(
                name=self._collection_name,
                metadata={"hnsw:space": "cosine"}
            )

            # Index policies if collection is empty
            existing = self._collection.count()
            if existing == 0:
                print("[RAG] Collection empty — indexing policies...")
                self._index_all_policies()
            else:
                print(f"[RAG] Collection ready — {existing} chunks indexed")

            self._ready = True
            return True

        except Exception as e:
            print(f"[RAG] Initialization failed: {e}")
            self._ready = False
            return False

    # ── Policy indexing ───────────────────────────────────────

    def _index_all_policies(self) -> int:
        """
        Load all JSON policy files and embed + store chunks.
        Returns count of chunks indexed.
        """
        if not self._policies_dir.exists():
            print(f"[RAG] Policies dir not found: {self._policies_dir}")
            return 0

        policy_files = list(self._policies_dir.glob("*.json"))
        if not policy_files:
            print("[RAG] No policy files found — adding defaults")
            self._index_default_policies()
            return 0

        all_chunks = []
        for pf in policy_files:
            try:
                with open(pf, "r", encoding="utf-8") as f:
                    policy = json.load(f)
                chunks = _build_chunks(policy)
                all_chunks.extend(chunks)
                print(f"[RAG]   Loaded {pf.name} → {len(chunks)} chunks")
            except Exception as e:
                print(f"[RAG]   Failed to load {pf.name}: {e}")

        if not all_chunks:
            return 0

        self._upsert_chunks(all_chunks)
        print(f"[RAG] Indexed {len(all_chunks)} total chunks")
        return len(all_chunks)

    def _upsert_chunks(self, chunks: list[dict]):
        """Embed and upsert chunks into ChromaDB."""
        texts     = [c["text"]     for c in chunks]
        ids       = [c["chunk_id"] for c in chunks]
        metadatas = [c["metadata"] for c in chunks]

        # Batch embed
        print(f"[RAG] Embedding {len(texts)} chunks...")
        t0 = time.perf_counter()
        embeddings = self._model.encode(
            texts,
            batch_size=32,
            show_progress_bar=False,
            convert_to_numpy=True,
        ).tolist()
        print(f"[RAG] Embedding done in {(time.perf_counter()-t0)*1000:.0f}ms")

        self._collection.upsert(
            ids        = ids,
            embeddings = embeddings,
            documents  = texts,
            metadatas  = metadatas,
        )

    def _index_default_policies(self):
        """
        Fallback: hardcoded default policies when no JSON files exist.
        Covers the most critical India-specific compliance rules.
        """
        defaults = [
            {
                "policy_id":   "DEFAULT-001",
                "group":       "general",
                "severity":    "CRITICAL",
                "description": "Default India PII protection",
                "rules": [
                    {
                        "rule_id":     "DEF-001",
                        "description": "Aadhaar numbers must never be shared externally",
                        "keywords":    ["aadhaar", "uid", "unique identification number"]
                    },
                    {
                        "rule_id":     "DEF-002",
                        "description": "PAN card numbers are confidential tax identifiers",
                        "keywords":    ["PAN", "permanent account number", "income tax id"]
                    },
                    {
                        "rule_id":     "DEF-003",
                        "description": "Cloud credentials must never leave secure vaults",
                        "keywords":    ["aws key", "secret key", "api token", "private key"]
                    },
                    {
                        "rule_id":     "DEF-004",
                        "description": "Database passwords and connection strings are restricted",
                        "keywords":    ["database password", "connection string", "db credentials"]
                    },
                ]
            }
        ]
        all_chunks = []
        for policy in defaults:
            all_chunks.extend(_build_chunks(policy))
        self._upsert_chunks(all_chunks)
        print(f"[RAG] Indexed {len(all_chunks)} default chunks")

    # ── Re-index (hot-reload support) ─────────────────────────

    def reindex(self) -> int:
        """
        Delete existing collection and re-index all policies.
        Called by policy hot-reload watcher when files change.
        """
        if not self._ready:
            return 0
        try:
            self._client.delete_collection(self._collection_name)
            self._collection = self._client.get_or_create_collection(
                name=self._collection_name,
                metadata={"hnsw:space": "cosine"}
            )
            count = self._index_all_policies()
            print(f"[RAG] Reindex complete — {count} chunks")
            return count
        except Exception as e:
            print(f"[RAG] Reindex failed: {e}")
            return 0

    # ── Query ─────────────────────────────────────────────────

    def query(
        self,
        text:            str,
        policy_groups:   Optional[list[str]] = None,
    ) -> RAGResult:
        """
        Semantically match clipboard text against indexed policies.

        Args:
            text:          clipboard text to check
            policy_groups: optional filter — only check these groups
                           (from classifier output). None = check all.

        Returns:
            RAGResult with is_violation=True if distance < threshold
        """
        if not self._ready:
            return RAGResult(is_violation=False, query_time_ms=0.0)

        if not text or not text.strip():
            return RAGResult(is_violation=False, query_time_ms=0.0)

        t_start = time.perf_counter()

        try:
            # Embed the query text
            query_embedding = self._model.encode(
                text[:2000],           # cap at 2KB for speed
                convert_to_numpy=True,
            ).tolist()

            # Build optional where filter for policy groups
            where = None
            if policy_groups:
                # ChromaDB $in operator for group filtering
                where = {"group": {"$in": policy_groups}}

            # Query ChromaDB
            results = self._collection.query(
                query_embeddings = [query_embedding],
                n_results        = min(self._top_k,
                                       self._collection.count()),
                where            = where,
                include          = ["distances", "metadatas", "documents"],
            )

            elapsed = (time.perf_counter() - t_start) * 1000

            # Parse results
            rag_result = RAGResult(
                is_violation  = False,
                query_time_ms = round(elapsed, 3),
            )

            if not results or not results["ids"][0]:
                return rag_result

            for i, doc_id in enumerate(results["ids"][0]):
                distance = results["distances"][0][i]
                metadata = results["metadatas"][0][i]
                document = results["documents"][0][i]

                match = RAGMatch(
                    policy_id   = metadata.get("policy_id",   "UNKNOWN"),
                    rule_id     = metadata.get("rule_id",     "UNKNOWN"),
                    description = metadata.get("description", ""),
                    distance    = round(distance, 4),
                    group       = metadata.get("group",       "general"),
                    severity    = metadata.get("severity",    "MEDIUM"),
                    chunk       = document[:200],
                )

                # Only flag as violation if within threshold
                if distance < self._distance_threshold:
                    rag_result.matches.append(match)
                    rag_result.is_violation = True

            # Sort matches by distance (closest first)
            rag_result.matches.sort(key=lambda m: m.distance)

            if rag_result.matches:
                rag_result.best_distance = rag_result.matches[0].distance

            return rag_result

        except Exception as e:
            print(f"[RAG] Query error: {e}")
            elapsed = (time.perf_counter() - t_start) * 1000
            return RAGResult(is_violation=False, query_time_ms=elapsed)

    # ── Status ────────────────────────────────────────────────

    @property
    def is_ready(self) -> bool:
        return self._ready

    @property
    def chunk_count(self) -> int:
        if self._collection is None:
            return 0
        return self._collection.count()

    def status(self) -> dict:
        return {
            "ready":      self._ready,
            "chunks":     self.chunk_count,
            "model":      self._model_name,
            "threshold":  self._distance_threshold,
            "chroma_dir": self._chroma_dir,
        }


# ── Module-level singleton ────────────────────────────────────

_rag_instance: Optional[RAGEngine] = None

def get_rag_engine() -> RAGEngine:
    global _rag_instance
    if _rag_instance is None:
        _rag_instance = RAGEngine()
    return _rag_instance


# ── Self-test ─────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"\n{'='*60}")
    print(f"  Blip Sentinel — RAGEngine Self-Test")
    print(f"{'='*60}\n")

    engine = RAGEngine(
        policies_dir = "./config/policies",
        chroma_dir   = "./data/chroma_db",
    )

    ok = engine.initialize()
    if not ok:
        print("  [FAIL] RAG engine failed to initialize")
        exit(1)

    print(f"\n  Status: {engine.status()}\n")

    test_cases = [
        (
            "AWS credentials",
            "aws_access_key_id=AKIAIOSFODNN7EXAMPLE aws_secret_access_key=abc123",
            None
        ),
        (
            "Aadhaar number context",
            "Please update the employee's aadhaar number in the HR system",
            ["finance"]
        ),
        (
            "DB connection string",
            "Connect using postgresql://admin:password@db.internal:5432/prod",
            ["engineering"]
        ),
        (
            "NDA clause",
            "This information is confidential and must not be disclosed to third parties",
            None
        ),
        (
            "Safe text",
            "Please review the attached meeting notes for tomorrow",
            None
        ),
    ]

    print(f"  {'Test':<30} {'Violation':<12} {'Distance':<10} {'Policy':<15} {'Time'}")
    print(f"  {'-'*30} {'-'*12} {'-'*10} {'-'*15} {'-'*8}")

    for label, text, groups in test_cases:
        result = engine.query(text, policy_groups=groups)
        violation = "VIOLATION" if result.is_violation else "CLEAN"
        best      = f"{result.best_distance:.4f}" if result.matches else "N/A"
        policy    = result.best_match.policy_id if result.best_match else "—"

        print(f"  {label:<30} {violation:<12} {best:<10} "
              f"{policy:<15} {result.query_time_ms:.1f}ms")

        if result.is_violation and result.best_match:
            print(f"  {'':30} Rule: {result.best_match.rule_id} — "
                  f"{result.best_match.description[:50]}")

    print(f"\n{'='*60}\n")