from __future__ import annotations

CWE_NAMES = {
    # Reported by the SAST scanners over BenchmarkJava.
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
    # Reported by the ZAP baseline over the running app.
    "CWE-200": "Sensitive Information Exposure",
    "CWE-264": "Permissions and Access Control Misconfiguration",
    "CWE-497": "Exposure of System Data to Unauthorized Control Sphere",
    "CWE-598": "Sensitive Data in GET Request Parameters",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-1021": "Improper Restriction of Rendered UI Layers (Clickjacking)",
}

# Coarse category per CWE, used to group and to retrieve knowledge documents.
CWE_CATEGORIES = {
    "CWE-200": "information_disclosure",
    "CWE-264": "access_control_misconfiguration",
    "CWE-497": "information_disclosure",
    "CWE-598": "information_disclosure",
    "CWE-693": "missing_security_control",
    "CWE-1021": "clickjacking",
}


def cwe_category(cwe: str, fallback: str = "uncategorized") -> str:
    return CWE_CATEGORIES.get(cwe, fallback)


def cwe_name(cwe: str, category: str = "") -> str:
    return CWE_NAMES.get(cwe, category.replace("_", " ").strip().title() or "Security weakness")
