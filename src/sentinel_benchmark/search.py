"""Small dependency-free knowledge/finding search for Week 2."""
from __future__ import annotations

import json
import math
import re
import sqlite3
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np

STOP = {"the", "a", "an", "and", "or", "of", "to", "in", "via", "for", "with", "on"}
ALIASES = {"sqli": "sql injection", "cross site scripting": "xss", "cross-site scripting": "xss", "cwe 89": "cwe-89", "cwe 79": "cwe-79"}

SEMANTIC_STOP = STOP | {
    "la", "va", "cua", "cho", "khi", "tu", "vao", "mot", "nhung", "nhu", "nao",
    "lam", "sao", "the", "duoc", "bi", "co", "khong", "trong", "ngoai", "ve",
}
SEMANTIC_CONCEPTS = (
    (
        {"sql", "cau lenh sql", "truy van co so du lieu", "database query", "sqli"},
        "sql injection sqli cwe-89 parameterized query prepared statement database injection",
    ),
    (
        {"script trinh duyet", "javascript khong tin cay", "chen script", "xss", "cross site scripting"},
        "cross site scripting xss cwe-79 browser script output encoding content security policy",
    ),
    (
        {"ngoai thu muc", "doc file tuy y", "duong dan file", "path traversal", "directory traversal"},
        "path traversal directory traversal cwe-22 file base directory canonicalize allowlist",
    ),
    (
        {"lenh he dieu hanh", "shell", "processbuilder", "command injection"},
        "os command injection shell processbuilder cwe-78 command argument allowlist",
    ),
    (
        {"server goi url", "mang noi bo", "metadata endpoint", "ssrf"},
        "server side request forgery ssrf cwe-918 url host scheme internal network redirect",
    ),
    (
        {"phan quyen", "vuot quyen", "authorization", "access control"},
        "broken access control authorization cwe-862 deny by default server side permission",
    ),
    (
        {"secret trong code", "mat khau trong code", "credential", "hardcoded secret"},
        "hardcoded secret credential cwe-798 secret manager environment rotation repository",
    ),
    (
        {"deserialize", "deserialization", "object khong tin cay"},
        "insecure deserialization cwe-502 untrusted object code execution allowlist type signature",
    ),
    (
        {"ma hoa yeu", "mat ma yeu", "thuat toan cu", "des", "weak cryptography"},
        "weak cryptography cwe-326 cwe-327 des aes gcm chacha key algorithm encryption",
    ),
    (
        {"khong xac thuc", "authentication", "dang nhap", "missing authentication"},
        "missing authentication cwe-306 endpoint middleware unauthorized access",
    ),
    (
        {"lo du lieu", "thong tin nhay cam", "pii", "information disclosure"},
        "sensitive data exposure information disclosure cwe-200 secret pii log error redact",
    ),
    (
        {"tranh chap", "dong thoi", "race condition", "concurrency"},
        "race condition concurrency cwe-362 lock isolation shared state simultaneous request",
    ),
)


def tokens(text: str) -> set[str]:
    return {x for x in re.findall(r"[a-z0-9]+", text.lower()) if x not in STOP}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def search(rows: list[dict[str, Any]], query: str, limit: int = 5) -> list[dict[str, Any]]:
    query = ALIASES.get(query.lower().strip(), query)
    wanted = tokens(query)
    ranked = []
    for row in rows:
        haystack = " ".join(str(row.get(k, "")) for k in ("title", "description", "content", "tags", "cwe", "owasp", "file_or_url"))
        present = tokens(haystack)
        score = len(wanted & present)
        if query.lower() in haystack.lower():
            score += 2
        if score:
            ranked.append((score, row))
    ranked.sort(key=lambda pair: (-pair[0], str(pair[1].get("title", ""))))
    return [row for _, row in ranked[:limit]]


def search_index(db_path: Path, query: str, kind: str = "knowledge", limit: int = 10, dataset: str | None = None, severity: str | None = None) -> list[dict[str, Any]]:
    query = ALIASES.get(query.lower().strip(), query)
    terms = [x for x in re.findall(r"[a-z0-9-]+", query.lower()) if x not in STOP]
    if not terms: return []
    # Quote each token so identifiers such as CWE-89 are treated as text, not FTS operators.
    params: list[Any] = [" OR ".join('"' + x.replace('"', '') + '"' for x in terms)]
    if kind == "findings":
        base = "SELECT d.*, bm25(findings_fts) AS rank FROM findings_fts f JOIN findings d ON d.observation_id=f.observation_id WHERE findings_fts MATCH ?"
        if dataset: base += " AND d.dataset=?"; params.append(dataset)
        if severity: base += " AND d.severity=?"; params.append(severity)
        base += " ORDER BY bm25(findings_fts) LIMIT ?"
    else:
        base = "SELECT k.*, bm25(knowledge_fts) AS rank FROM knowledge_fts f JOIN knowledge k ON k.document_id=f.document_id WHERE knowledge_fts MATCH ? ORDER BY bm25(knowledge_fts) LIMIT ?"
    params.append(limit)
    conn = sqlite3.connect(db_path); conn.row_factory = sqlite3.Row
    try:
        return [dict(x) for x in conn.execute(base, params).fetchall()]
    finally:
        conn.close()


def normalize_semantic_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text.lower())
    return "".join(character for character in normalized if not unicodedata.combining(character))


def expand_semantic_query(query: str) -> str:
    normalized = normalize_semantic_text(query)
    expansions = [query]
    for triggers, concept in SEMANTIC_CONCEPTS:
        if any(
            re.search(rf"\b{re.escape(trigger)}\b", normalized)
            if re.fullmatch(r"[a-z0-9]+", trigger)
            else trigger in normalized
            for trigger in triggers
        ):
            expansions.append(concept)
    cwe = re.search(r"cwe[\s-]?(\d+)", normalized)
    if cwe:
        expansions.append(f"cwe-{cwe.group(1)}")
    return " ".join(expansions)


def semantic_features(text: str) -> list[str]:
    words = [
        word
        for word in re.findall(r"[a-z0-9]+", normalize_semantic_text(text))
        if word not in SEMANTIC_STOP and len(word) > 1
    ]
    return words + [f"{left}_{right}" for left, right in zip(words, words[1:])]


def knowledge_text(row: dict[str, Any]) -> str:
    tags = row.get("tags", "")
    if isinstance(tags, str):
        try:
            tags = " ".join(json.loads(tags))
        except (TypeError, json.JSONDecodeError):
            pass
    return " ".join(str(row.get(key, "")) for key in ("title", "source", "content")) + f" {tags}"


def build_tfidf(texts: list[str]) -> tuple[np.ndarray, dict[str, int], np.ndarray]:
    document_features = [Counter(semantic_features(text)) for text in texts]
    vocabulary = sorted({feature for features in document_features for feature in features})
    positions = {feature: index for index, feature in enumerate(vocabulary)}
    document_frequency = Counter(
        feature for features in document_features for feature in features
    )
    idf = np.array(
        [math.log((1 + len(texts)) / (1 + document_frequency[feature])) + 1 for feature in vocabulary],
        dtype=float,
    )
    matrix = np.zeros((len(texts), len(vocabulary)), dtype=float)
    for row_index, features in enumerate(document_features):
        for feature, count in features.items():
            matrix[row_index, positions[feature]] = (1 + math.log(count)) * idf[positions[feature]]
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    return np.divide(matrix, norms, out=np.zeros_like(matrix), where=norms != 0), positions, idf


def vectorize_query(query: str, positions: dict[str, int], idf: np.ndarray) -> np.ndarray:
    vector = np.zeros(len(positions), dtype=float)
    for feature, count in Counter(semantic_features(expand_semantic_query(query))).items():
        index = positions.get(feature)
        if index is not None:
            vector[index] = (1 + math.log(count)) * idf[index]
    norm = np.linalg.norm(vector)
    return vector / norm if norm else vector


def semantic_rank(rows: list[dict[str, Any]], query: str, limit: int = 5) -> list[dict[str, Any]]:
    if not query.strip() or not rows:
        return []
    matrix, positions, idf = build_tfidf([knowledge_text(row) for row in rows])
    query_vector = vectorize_query(query, positions, idf)
    if not np.any(query_vector):
        return []

    direct_scores = matrix @ query_vector
    component_count = min(6, max(1, len(rows) - 1), max(1, matrix.shape[1] - 1))
    u, singular_values, vt = np.linalg.svd(matrix, full_matrices=False)
    document_latent = u[:, :component_count] * singular_values[:component_count]
    query_latent = query_vector @ vt[:component_count].T
    document_norms = np.linalg.norm(document_latent, axis=1)
    query_norm = np.linalg.norm(query_latent)
    if query_norm:
        latent_scores = np.divide(
            document_latent @ query_latent,
            document_norms * query_norm,
            out=np.zeros(len(rows), dtype=float),
            where=document_norms != 0,
        )
    else:
        latent_scores = np.zeros(len(rows), dtype=float)

    scores = 0.35 * np.clip(direct_scores, 0, 1) + 0.65 * np.clip(latent_scores, 0, 1)
    ranked = []
    for position in np.argsort(-scores):
        score = float(scores[position])
        if score <= 0:
            continue
        result = dict(rows[int(position)])
        result.update({"score": round(score, 6), "rank": round(score, 6), "retrieval_mode": "semantic_lsa"})
        ranked.append(result)
        if len(ranked) >= limit:
            break
    return ranked


def load_knowledge(db_path: Path) -> list[dict[str, Any]]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute("SELECT * FROM knowledge ORDER BY document_id")]


def semantic_search_index(db_path: Path, query: str, limit: int = 5) -> list[dict[str, Any]]:
    return semantic_rank(load_knowledge(db_path), query, limit)


def hybrid_search_index(db_path: Path, query: str, limit: int = 5) -> list[dict[str, Any]]:
    rows = load_knowledge(db_path)
    keyword = search_index(db_path, query, "knowledge", len(rows))
    semantic = semantic_rank(rows, query, len(rows))
    by_id = {row["document_id"]: row for row in rows}
    scores: dict[str, float] = {}
    details: dict[str, dict[str, Any]] = {}
    for position, row in enumerate(keyword, start=1):
        document_id = row["document_id"]
        scores[document_id] = scores.get(document_id, 0.0) + 0.15 / position
        details.setdefault(document_id, {})["keyword_position"] = position
    for position, row in enumerate(semantic, start=1):
        document_id = row["document_id"]
        scores[document_id] = scores.get(document_id, 0.0) + 0.85 * row["score"]
        details.setdefault(document_id, {}).update(
            {"semantic_position": position, "semantic_score": row["score"]}
        )
    if not scores:
        return []
    maximum = max(scores.values())
    ranked = []
    for document_id, score in sorted(scores.items(), key=lambda item: (-item[1], item[0]))[:limit]:
        result = dict(by_id[document_id])
        result.update(details[document_id])
        result.update({"score": round(score / maximum, 6), "rank": round(score / maximum, 6), "retrieval_mode": "hybrid_weighted"})
        ranked.append(result)
    return ranked
