from __future__ import annotations

CWE_NAMES = {
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-90": "LDAP Injection",
    "CWE-327": "Broken or Risky Cryptographic Algorithm",
    "CWE-328": "Reversible One-Way Hash",
    "CWE-330": "Insufficiently Random Values",
    "CWE-501": "Trust Boundary Violation",
    "CWE-614": "Sensitive Cookie Without Secure Flag",
}


def cwe_name(cwe: str, category: str = "") -> str:
    return CWE_NAMES.get(cwe, category.replace("_", " ").strip().title() or "Security weakness")
