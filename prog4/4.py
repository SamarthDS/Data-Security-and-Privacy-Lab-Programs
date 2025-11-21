#!/usr/bin/env python3
"""
Vulnerability Analyser Tool (educational, defensive)

- Scans files (single file or entire directory) for common insecure patterns across languages.
- Outputs a human-readable report and can export JSON.
- DOES NOT perform any network activity or modify files.
- Use for code-review, training, or auditing in safe/authorized contexts only.

Example:
    python vuln_analyzer.py -d ./myproject --json-report report.json

Author: ChatGPT (educational)
"""

from pathlib import Path
import re
import argparse
import json
from datetime import datetime
from typing import List, Dict, Any

# ---------- Rules: pattern, name, severity, languages, explanation, suggestion ----------
RULES = [
    {
        "id": "hardcoded-cred",
        "pattern": re.compile(
            r"\b(?:(?:api[_-]?key|apikey|secret|password|passwd|pwd|token|access[_-]?token|private[_-]?key)\b)\s*[:=]\s*['\"`][^'\"`]{4,}['\"`]",
            re.IGNORECASE,
        ),
        "name": "Hardcoded credential / secret",
        "severity": "HIGH",
        "languages": ["any"],
        "explanation": "Secrets like API keys, tokens, or passwords found directly in source code are easily leaked or committed to VCS.",
        "suggestion": "Move secrets to environment variables, secret managers (Vault, AWS Secrets Manager), or config files excluded from VCS. Rotate existing secrets.",
    },
    {
        "id": "eval-exec",
        "pattern": re.compile(r"\b(eval|exec|Runtime\.getRuntime\(\)\.exec|system\()"),
        "name": "Use of eval/exec or direct shell execution",
        "severity": "HIGH",
        "languages": ["python", "java", "c", "js", "any"],
        "explanation": "Dynamic code execution or arbitrary shell invocation may lead to code injection if inputs aren't strictly controlled.",
        "suggestion": "Avoid eval/exec. Use safe parsing, parameterized libraries, or restricted APIs. Use subprocess without shell=True and validate inputs.",
    },
    {
        "id": "subprocess-shell-true",
        "pattern": re.compile(r"subprocess\.[Pp]open\(.+shell\s*=\s*True", re.DOTALL),
        "name": "subprocess with shell=True",
        "severity": "HIGH",
        "languages": ["python"],
        "explanation": "Using shell=True can allow shell injection when passing unsanitized input.",
        "suggestion": "Use list arguments (argv) and avoid shell=True. Validate or sanitize user-controlled input.",
    },
    {
        "id": "os-system",
        "pattern": re.compile(r"\b(os\.system|popen\(|system\()"),
        "name": "Direct system call",
        "severity": "HIGH",
        "languages": ["python", "c", "any"],
        "explanation": "Direct system calls may accidentally execute attacker-controlled data.",
        "suggestion": "Use safe APIs and validate inputs; prefer language-level libraries instead of shelling out.",
    },
    {
        "id": "insecure-temp",
        "pattern": re.compile(r"\b(tempfile\.mktemp|tmpnam|mktemp\()"),
        "name": "Insecure temporary file usage",
        "severity": "HIGH",
        "languages": ["python", "c"],
        "explanation": "Functions like mktemp can lead to predictable filenames and race conditions.",
        "suggestion": "Use secure temp file APIs (tempfile.NamedTemporaryFile, mkstemp) and proper permissions.",
    },
    {
        "id": "pickle-loads",
        "pattern": re.compile(r"\bpickle\.loads?\("),
        "name": "Untrusted pickle deserialization",
        "severity": "HIGH",
        "languages": ["python"],
        "explanation": "pickle.loads on untrusted data can lead to remote code execution.",
        "suggestion": "Use safe serialization (JSON) or vetted deserialization libraries. Authenticate and validate inputs.",
    },
    {
        "id": "sql-concat",
        "pattern": re.compile(
            r"""(?ix)         # ignorecase, verbose
            (?:execute|query|executeQuery|prepareStatement|sql)\s*\(.*?      # call to DB exec
            (?:(?:"[^"]*'|\b\+|\bstring%))  # string concatenation-like patterns (heuristic)
            """,
            re.DOTALL,
        ),
        "name": "Possible SQL concatenation / injection",
        "severity": "HIGH",
        "languages": ["any"],
        "explanation": "Constructing SQL with string concatenation may enable SQL injection if user input is included.",
        "suggestion": "Use parameterized queries / prepared statements or ORM query APIs. Sanitize inputs.",
    },
    {
        "id": "http-insecure",
        "pattern": re.compile(r"\bhttps?://[^'\")\]\s]+"),
        "name": "Explicit HTTP/HTTPS endpoint",
        "severity": "LOW",
        "languages": ["any"],
        "explanation": "Hardcoded endpoints may leak sensitive endpoints or usage of http (non-TLS) is insecure.",
        "suggestion": "Avoid embedding secrets in URLs; prefer configuration. Use HTTPS (TLS) and validate certs.",
    },
    {
        "id": "weak-crypto",
        "pattern": re.compile(r"\b(MD5|md5|SHA1|sha1|DES\(|des\()"),
        "name": "Use of weak cryptographic functions",
        "severity": "MEDIUM",
        "languages": ["any"],
        "explanation": "MD5 and SHA1 are considered broken/weak for cryptographic purposes.",
        "suggestion": "Use modern algorithms (SHA-256+), and higher-level libraries (libsodium, cryptography).",
    },
    {
        "id": "http-verify-false",
        "pattern": re.compile(r"\brequests\..*\(.*verify\s*=\s*False"),
        "name": "Requests verify=False (TLS verification disabled)",
        "severity": "HIGH",
        "languages": ["python"],
        "explanation": "Disabling certificate verification exposes to man-in-the-middle attacks.",
        "suggestion": "Don't disable verification; install proper CA bundles or provide cert paths.",
    },
    {
        "id": "insecure-c-functions",
        "pattern": re.compile(r"\b(gets|strcpy|strcat|sprintf|vsprintf)\s*\("),
        "name": "Use of unsafe C string functions",
        "severity": "HIGH",
        "languages": ["c", "cpp"],
        "explanation": "Functions like gets/strcpy are buffer-overflow-prone.",
        "suggestion": "Use safer alternatives (fgets, strncpy_s, snprintf) and bounds checking.",
    },
    {
        "id": "base64-cred",
        "pattern": re.compile(r"\b(base64|b64decode|atob)\s*\(\s*['\"][A-Za-z0-9+/=]{16,}['\"]\s*\)"),
        "name": "Encoded secret in source",
        "severity": "MEDIUM",
        "languages": ["any"],
        "explanation": "Secrets encoded with base64 in source are still secrets and can be trivially decoded.",
        "suggestion": "Remove secrets from source; use secret management.",
    },
    {
        "id": "insecure-perms-chmod",
        "pattern": re.compile(r"\b(chmod|os\.chmod)\s*\(.+?(?:0o?7+|0777)"),
        "name": "Insecure file permissions (chmod 777)",
        "severity": "MEDIUM",
        "languages": ["any"],
        "explanation": "Setting overly permissive file modes can expose secrets.",
        "suggestion": "Use least-privilege permissions (600/640/700) as appropriate.",
    },
    {
        "id": "unsafe-random",
        "pattern": re.compile(r"\b(rand\(|random\(|Math\.random\(|random\.)"),
        "name": "Use of non-cryptographic RNG for security",
        "severity": "MEDIUM",
        "languages": ["any"],
        "explanation": "General-purpose RNGs are not suitable for cryptographic secrets.",
        "suggestion": "Use secure RNGs (os.urandom, secrets module, /dev/urandom, crypto RNGs).",
    },
    # Add more rules as needed...
]

# ---------- Helper functions ----------


def detect_in_text(text: str, rule: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return list of matches with line number and snippet for a text using a rule."""
    matches = []
    # We'll search line-by-line to provide accurate line numbers and snippet context
    for i, line in enumerate(text.splitlines(), start=1):
        if rule["pattern"].search(line):
            snippet = line.strip()
            matches.append({"line": i, "snippet": snippet})
    return matches


def is_text_file(path: Path) -> bool:
    """Heuristic to skip binary files."""
    try:
        CHUNK = 1024
        with open(path, "rb") as f:
            data = f.read(CHUNK)
            # if it contains null bytes it's likely binary
            if b"\x00" in data:
                return False
        return True
    except Exception:
        return False


def language_from_suffix(path: Path) -> str:
    suf = path.suffix.lower()
    mapping = {
        ".py": "python",
        ".js": "js",
        ".java": "java",
        ".c": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".h": "c",
        ".php": "php",
        ".rb": "ruby",
        ".go": "go",
        ".rs": "rust",
        ".cs": "csharp",
        ".sh": "sh",
        ".ps1": "powershell",
        ".swift": "swift",
    }
    return mapping.get(suf, "any")


def match_rule_applicable(rule: Dict[str, Any], language: str) -> bool:
    langs = rule.get("languages", ["any"])
    return "any" in langs or language in langs


# ---------- Core scanning ----------


def scan_file(path: Path) -> List[Dict[str, Any]]:
    """Scan single file and return list of findings."""
    findings = []
    if not path.exists() or not path.is_file():
        return findings
    if not is_text_file(path):
        return findings

    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    lang = language_from_suffix(path)
    for rule in RULES:
        if not match_rule_applicable(rule, lang):
            continue
        matches = detect_in_text(text, rule)
        for m in matches:
            findings.append(
                {
                    "file": str(path),
                    "line": m["line"],
                    "snippet": m["snippet"],
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "explanation": rule["explanation"],
                    "suggestion": rule["suggestion"],
                }
            )
    return findings


def scan_path(base: Path, recursive: bool = True, ignore_patterns: List[str] = None) -> List[Dict[str, Any]]:
    """Scan a directory or file path. Returns all findings."""
    findings = []
    ignore_patterns = ignore_patterns or []
    if base.is_file():
        return scan_file(base)

    for p in base.rglob("*") if recursive else base.glob("*"):
        if p.is_dir():
            continue
        # simple ignore matching
        if any(p.match(ip) or ip in str(p) for ip in ignore_patterns):
            continue
        findings.extend(scan_file(p))
    return findings


# ---------- Reporting ----------


def summarise_findings(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    summary = {"total_findings": len(findings), "by_severity": {}, "by_rule": {}}
    for f in findings:
        sev = f["severity"]
        summary["by_severity"].setdefault(sev, 0)
        summary["by_severity"][sev] += 1
        rid = f["rule_id"]
        summary["by_rule"].setdefault(rid, 0)
        summary["by_rule"][rid] += 1
    return summary


def print_report(findings: List[Dict[str, Any]], quiet: bool = False):
    if not findings:
        print("No issues found.")
        return
    findings_sorted = sorted(findings, key=lambda x: (x["severity"], x["file"], x["line"]), reverse=False)
    print("=" * 80)
    print(f"Vulnerability Analysis Report - {datetime.utcnow().isoformat()} UTC")
    print(f"Total findings: {len(findings)}")
    print("=" * 80)
    for f in findings_sorted:
        print(f"{f['severity']}: {f['rule_name']} — {f['file']}:{f['line']}")
        print(f"  snippet: {f['snippet']}")
        print(f"  why: {f['explanation']}")
        print(f"  fix: {f['suggestion']}")
        print("-" * 80)
    summary = summarise_findings(findings)
    print("\nSummary:")
    print(json.dumps(summary, indent=2))


def save_json_report(findings: List[Dict[str, Any]], path: Path):
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "findings": findings,
        "summary": summarise_findings(findings),
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"JSON report saved to {path}")


# ---------- CLI ----------


def main():
    parser = argparse.ArgumentParser(description="Simple Vulnerability Analyzer (educational).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--dir", help="Directory to scan", type=str)
    group.add_argument("-f", "--file", help="Single file to scan", type=str)
    parser.add_argument("--no-recursive", help="Do not traverse directories recursively", action="store_true")
    parser.add_argument("--ignore", help="Comma-separated list of patterns to ignore (path substrings or globs)", default="")
    parser.add_argument("--json-report", help="Write JSON report to this file", default=None)
    parser.add_argument("--quiet", help="Minimal output", action="store_true")
    args = parser.parse_args()

    base = Path(args.file) if args.file else Path(args.dir)
    recursive = not args.no_recursive
    ignore_patterns = [x.strip() for x in args.ignore.split(",") if x.strip()]

    print(f"Scanning {base} (recursive={recursive}) ...")
    findings = scan_path(base, recursive=recursive, ignore_patterns=ignore_patterns)
    if not args.quiet:
        print_report(findings)
    if args.json_report:
        save_json_report(findings, Path(args.json_report))


if __name__ == "__main__":
    main()
