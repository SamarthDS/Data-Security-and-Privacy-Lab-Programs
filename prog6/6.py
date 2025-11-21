#!/usr/bin/env python3
"""
Safe static pre-open file scanner (educational).
Does NOT execute the file. Only static checks & heuristics.
"""

import os
import sys
import hashlib
import math
import mimetypes
import re

# Optional imports (wrap in try/except so script runs even if not installed)
try:
    import magic  # python-magic
except Exception:
    magic = None

try:
    import pefile
except Exception:
    pefile = None

try:
    # oletools' olevba to detect VBA macros in Office documents (older binary and OOXML)
    from oletools.olevba import VBA_Parser
except Exception:
    VBA_Parser = None

try:
    import requests
except Exception:
    requests = None

# ---------- Utility functions ----------
def file_hashes(path):
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h_md5.update(chunk)
            h_sha1.update(chunk)
            h_sha256.update(chunk)
    return h_md5.hexdigest(), h_sha1.hexdigest(), h_sha256.hexdigest()

def detect_type(path):
    # Prefer python-magic if available
    if magic:
        try:
            m = magic.Magic(mime=True)
            mime = m.from_file(path)
            return mime
        except Exception:
            pass
    # fallback to mimetypes
    mime, _ = mimetypes.guess_type(path)
    return mime or 'unknown/unknown'

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent

def sample_entropy(path, sample_size=65536):
    with open(path, 'rb') as f:
        data = f.read(sample_size)
    return shannon_entropy(data)

# ---------- Heuristic checks ----------
SUSPICIOUS_STRINGS = [
    b"powershell", b"Invoke-Expression", b"IEX ", b"cmd.exe", b"cmd ", b"downloadstring",
    b"CreateRemoteThread", b"VirtualAllocEx", b"VirtualProtect", b"WriteProcessMemory",
    b"rundll32", b"msiexec", b"Base64", b"base64", b"GetObject(", b"WScript.Shell",
    b"ActiveXObject", b"shell.application", b"https://", b"http://", b"@gmail.com", b"@yahoo.com"
]
URL_RE = re.compile(rb"https?://[^\s'\"<>]+")

# ---------- File-type specific analysis ----------
def analyze_pe(path):
    findings = []
    if not pefile:
        findings.append("pefile library not installed; skipping PE analysis")
        return findings
    try:
        p = pefile.PE(path, fast_load=True)
        p.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
        ])
    except Exception as e:
        findings.append(f"PE parsing failed: {e}")
        return findings

    # suspicious imported APIs often used by malware
    suspicious_apis = {
        "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "LoadLibraryA",
        "LoadLibraryW", "GetProcAddress", "InternetOpenUrlA", "InternetOpen", "WinExec",
        "ShellExecuteA", "ShellExecuteW", "URLDownloadToFileA", "URLDownloadToFileW"
    }
    imported = set()
    try:
        for entry in getattr(p, 'DIRECTORY_ENTRY_IMPORT', []):
            for imp in entry.imports:
                if imp.name:
                    imported.add(imp.name.decode(errors='ignore'))
    except Exception:
        pass

    found_sus = suspicious_apis.intersection(imported)
    if found_sus:
        findings.append(f"suspicious imported APIs: {', '.join(list(found_sus)[:10])}")
    # Check sections with unusual names or high entropy
    try:
        for sec in p.sections:
            name = sec.Name.rstrip(b'\x00').decode(errors='ignore')
            ent = shannon_entropy(sec.get_data())
            if ent > 7.5:
                findings.append(f"high entropy in section '{name}' (entropy={ent:.2f}) -> possibly packed/obfuscated")
            if name.lower() in ['.rsrc', '.data', '.text'] and sec.SizeOfRawData == 0:
                findings.append(f"weird section {name} with zero raw size")
            if name.startswith('.') is False:
                findings.append(f"odd section name: {name}")
    except Exception:
        pass

    return findings

def analyze_office(path):
    findings = []
    if not VBA_Parser:
        findings.append("oletools not installed; skipping Office macro analysis")
        return findings
    try:
        vb = VBA_Parser(path)
        if vb.detect_vba_macros():
            findings.append("document contains VBA macros")
            for (subfile, stream_path, vba_filename, vba_code) in vb.extract_macros():
                # naive check for suspicious keywords in macro code
                low = vba_code.lower()
                for kw in [b"shell", b"powershell", b"createshell", b"wscript", b"downloadfile", b"urldownloadtofile"]:
                    if kw.decode() in low:
                        findings.append(f"suspicious macro code keyword: {kw.decode()} in {vba_filename}")
                if "autoopen" in low or "autopen" in low or "document_open" in low:
                    findings.append("macro defines auto-run (AutoOpen/Document_Open)")
        else:
            findings.append("no VBA macros detected")
    except Exception as e:
        findings.append(f"oletools parsing error: {e}")
    return findings

# ---------- Optional VirusTotal lookup (requires API key) ----------
def virustotal_lookup_sha256(sha256, api_key):
    if not requests:
        return {"error": "requests not installed"}
    url = "https://www.virustotal.com/api/v3/files/" + sha256
    headers = {"x-apikey": api_key}
    r = requests.get(url, headers=headers, timeout=15)
    if r.status_code == 200:
        return r.json()
    else:
        return {"error": f"vt lookup failed status {r.status_code}", "content": r.text}

# ---------- Main scanner ----------
def scan_file(path, vt_api_key=None):
    report = {"path": path, "size": os.path.getsize(path)}
    report['hashes'] = {}
    md5, sha1, sha256 = file_hashes(path)
    report['hashes']['md5'] = md5
    report['hashes']['sha1'] = sha1
    report['hashes']['sha256'] = sha256

    report['mime'] = detect_type(path)
    report['ext'] = os.path.splitext(path)[1].lower()
    report['entropy_sample'] = sample_entropy(path)

    # extension mismatch
    guessed_ext = None
    mime = report['mime'] or ''
    if 'pe' in mime or path.lower().endswith(('.exe', '.dll', '.sys')):
        guessed_ext = '.exe/dll'
    elif 'officedocument' in mime or path.lower().endswith(('.docx', '.xlsx', '.pptx', '.doc', '.xls', '.ppt')):
        guessed_ext = '.office'
    elif 'pdf' in mime or path.lower().endswith('.pdf'):
        guessed_ext = '.pdf'
    if guessed_ext and guessed_ext not in report['ext']:
        report.setdefault('warnings', []).append(f"extension mismatch: detected type {guessed_ext} but extension is {report['ext']}")

    # read first chunk for string checks
    with open(path, 'rb') as f:
        sample = f.read(65536)
    low_sample = sample.lower()

    # suspicious string checks
    found_strings = []
    for s in SUSPICIOUS_STRINGS:
        if s.lower() in low_sample:
            found_strings.append(s.decode(errors='ignore'))
    # URL find
    urls = URL_RE.findall(sample)
    report['suspicious_strings'] = found_strings
    report['urls_found'] = [u.decode(errors='ignore') for u in urls]

    # heuristic risk scoring (very simple)
    risk_points = 0
    if report['entropy_sample'] > 7.5:
        risk_points += 2
    if found_strings:
        risk_points += min(3, len(found_strings))
    if urls:
        risk_points += 2
    if 'warnings' in report:
        risk_points += 1

    # file-type specific
    report['type_findings'] = []
    # PE
    if path.lower().endswith(('.exe', '.dll')) or 'pe' in mime:
        report['type_findings'].extend(analyze_pe(path))
        if any('suspicious' in t.lower() for t in report['type_findings']):
            risk_points += 2

    # Office / Macros
    if path.lower().endswith(('.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm', '.docx', '.xlsx', '.pptx')) or 'officedocument' in mime:
        report['type_findings'].extend(analyze_office(path))
        if any('macros' in t.lower() for t in report['type_findings']):
            risk_points += 3

    # Optional VirusTotal
    if vt_api_key:
        try:
            vt = virustotal_lookup_sha256(sha256, vt_api_key)
            report['virustotal'] = vt
            # crude: if vt returns analysis stats, check positives
            if isinstance(vt, dict) and 'data' in vt and 'attributes' in vt['data']:
                stats = vt['data']['attributes'].get('last_analysis_stats', {})
                positives = sum(v for k, v in stats.items() if k in ('malicious', 'suspicious'))
                if positives > 0:
                    report.setdefault('warnings', []).append(f"VirusTotal detection: {positives} engines flagged it")
                    risk_points += 5
        except Exception as e:
            report.setdefault('warnings', []).append(f"VirusTotal lookup failed: {e}")

    # final risk level
    if risk_points >= 8:
        risk = "HIGH"
    elif risk_points >= 4:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    report['risk_points'] = risk_points
    report['risk'] = risk

    # Suggest probable attack types depending on findings (educational)
    probable_attacks = set()
    s_all = " ".join(report.get('suspicious_strings', [])).lower()
    tf = " ".join(report.get('type_findings', [])).lower()
    if 'ransom' in s_all or 'encrypt' in s_all or 'ransom' in tf:
        probable_attacks.add('Ransomware (file encryption)')
    if any(x in s_all for x in ['powershell', 'downloadstring', 'url']):
        probable_attacks.add('Downloader / Remote fetcher (downloads additional payloads)')
    if any(x in tf for x in ['createremotethread', 'virtualallocex', 'writeprocessmemory']):
        probable_attacks.add('Process injection / Remote code execution (advanced malware)')
    if 'macro' in tf:
        probable_attacks.add('Macro-based infection (Office macros, may run on open)')
    if urls:
        probable_attacks.add('Phishing / Command-and-control / Data exfiltration via network')
    if report['entropy_sample'] > 7.5:
        probable_attacks.add('Packed/obfuscated binary (often used by malware to evade detection)')
    if not probable_attacks:
        probable_attacks.add('Possible information-stealer / Trojan / Unknown — further analysis recommended')

    report['probable_attacks'] = sorted(list(probable_attacks))
    return report

# ---------- CLI ----------
def print_report(r):
    print(f"File: {r['path']}")
    print(f"Size: {r['size']} bytes")
    print("Hashes:")
    for k,v in r['hashes'].items():
        print(f"  {k}: {v}")
    print(f"Detected MIME type: {r.get('mime')}")
    print(f"Extension: {r.get('ext')}")
    print(f"Sample entropy: {r.get('entropy_sample'):.2f}")
    if r.get('warnings'):
        print("\nWarnings:")
        for w in r['warnings']:
            print(" -", w)
    if r.get('suspicious_strings'):
        print("\nSuspicious strings found (sample):")
        for s in r['suspicious_strings'][:10]:
            print(" -", s)
    if r.get('urls_found'):
        print("\nURLs found in file (sample):")
        for u in r['urls_found'][:10]:
            print(" -", u)
    if r.get('type_findings'):
        print("\nType-specific findings:")
        for t in r['type_findings']:
            print(" -", t)
    print("\nRisk assessment:")
    print(f"  Risk points: {r['risk_points']}, Level: {r['risk']}")
    print("\nProbable attack types if executed/opened:")
    for a in r['probable_attacks']:
        print(" -", a)
    if r.get('virustotal'):
        print("\nVirusTotal info attached (see vt data in JSON)")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python safe_scan.py <file> [--vt-api-key=KEY]")
        sys.exit(1)
    path = sys.argv[1]
    vt_key = None
    for arg in sys.argv[2:]:
        if arg.startswith("--vt-api-key="):
            vt_key = arg.split("=",1)[1]
    rep = scan_file(path, vt_key)
    print_report(rep)
