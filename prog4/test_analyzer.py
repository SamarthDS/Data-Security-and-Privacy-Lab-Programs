import subprocess

def run_test():
    print("=== Running Vulnerability Analyzer Test ===")
    result = subprocess.run(
        ["python3", "vuln_analyzer.py", "vulnerable_test.py"],
        capture_output=True,
        text=True
    )
    print(result.stdout)
    if result.stderr:
        print("Error:", result.stderr)
