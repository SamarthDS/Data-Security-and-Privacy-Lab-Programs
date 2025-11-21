# Vulnerability Analyzer - Streamlit Web Application

An interactive web-based vulnerability analysis tool for educational purposes. This application provides a user-friendly interface to analyze source code for common security vulnerabilities.

## 🚀 Quick Start

1. **Start the application:**
   ```bash
   cd /Users/namratha/Desktop/python/dsp-2/4
   /Users/namratha/Desktop/python/dsp-2/.venv/bin/python -m streamlit run streamlit_vuln_app.py
   ```

2. **Open your browser:**
   Navigate to `http://localhost:8501`

## ✨ Features

### 📂 Multiple Input Methods
- **File Upload**: Upload source code files directly
- **Code Paste**: Paste code snippets for quick analysis
- **Example Code**: Pre-loaded vulnerable code examples for learning

### 🔍 Comprehensive Analysis
- **Multi-language Support**: Python, JavaScript, Java, C/C++, PHP, Ruby, Go, Rust, C#, Shell
- **Severity Classification**: HIGH, MEDIUM, LOW risk levels
- **Detailed Explanations**: Why each issue is problematic
- **Fix Suggestions**: How to remediate each vulnerability

### 📊 Interactive Visualizations
- **Severity Distribution**: Pie chart showing risk breakdown
- **Vulnerability Types**: Bar chart of most common issues
- **Line Distribution**: Line chart showing issue locations
- **Real-time Filtering**: Filter by severity and rule type

### 🎯 Vulnerability Detection
The tool detects various security issues including:

#### HIGH Severity
- **Hardcoded Secrets**: API keys, passwords, tokens in source code
- **Code Injection**: eval(), exec(), dynamic code execution
- **Command Injection**: Shell injection, unsafe system calls
- **Unsafe Deserialization**: pickle.loads() vulnerabilities
- **SSL/TLS Issues**: Disabled certificate verification
- **Insecure File Operations**: Unsafe temporary files

#### MEDIUM Severity
- **Weak Cryptography**: MD5, SHA1, deprecated algorithms
- **File Permissions**: Overly permissive chmod settings
- **Random Number Generation**: Non-cryptographic RNGs for security

#### LOW Severity
- **Information Disclosure**: Hardcoded URLs, endpoints
- **Configuration Issues**: Minor security misconfigurations

## 🖥️ User Interface

### Sidebar Controls
- **Input Method Selection**: Choose how to provide code
- **File Upload Interface**: Drag & drop or browse files
- **Help Sections**: Severity explanations and supported languages

### Main Dashboard
- **File Information**: Size, line count, language detection
- **Code Preview**: Syntax-highlighted code display
- **Analysis Results**: Interactive charts and metrics
- **Vulnerability Details**: Expandable issue descriptions
- **Export Options**: Download JSON reports

### Interactive Features
- **Real-time Filtering**: Filter results by severity and type
- **Sorting Options**: Sort by severity, line number, or rule type
- **Detailed View**: Expand issues for full explanations
- **Export Reports**: Download findings as JSON

## 📚 Example Vulnerable Code

The application includes several example vulnerable code snippets:

### 1. Hardcoded Secrets
```python
API_KEY = "sk-1234567890abcdef"  # HIGH: Exposed API key
password = "mypassword123"       # HIGH: Hardcoded password
```

### 2. SQL Injection
```python
# Vulnerable: string concatenation in SQL
query = f"SELECT * FROM users WHERE id = {user_id}"
```

### 3. Command Injection
```python
# Vulnerable: shell=True with user input
subprocess.run(f"cp {filename} backup/", shell=True)
```

### 4. Weak Cryptography
```python
# Vulnerable: MD5 is cryptographically broken
hashlib.md5(password.encode()).hexdigest()
```

## 🛡️ Security Rules

The analyzer implements comprehensive security rules:

### Code Injection Prevention
- Detects `eval()`, `exec()` usage
- Identifies unsafe subprocess calls
- Flags dynamic code execution patterns

### Secret Management
- Finds hardcoded API keys, passwords, tokens
- Detects base64-encoded secrets
- Identifies credential patterns

### Cryptography Best Practices
- Flags weak hash functions (MD5, SHA1)
- Identifies non-cryptographic random usage
- Detects deprecated encryption methods

### Input Validation
- Shell injection detection
- SQL injection patterns
- Path traversal vulnerabilities

## 📥 Export & Reporting

### JSON Report Structure
```json
{
  "generated_at": "2025-09-10T04:37:02.203793Z",
  "findings": [
    {
      "file": "example.py",
      "line": 15,
      "snippet": "API_KEY = \"sk-123\"",
      "rule_id": "hardcoded-cred",
      "rule_name": "Hardcoded credential / secret",
      "severity": "HIGH",
      "explanation": "...",
      "suggestion": "..."
    }
  ],
  "summary": {
    "total_findings": 5,
    "by_severity": {"HIGH": 3, "MEDIUM": 2},
    "by_rule": {"hardcoded-cred": 2, "eval-exec": 1}
  }
}
```

## 🎓 Educational Use Cases

### Security Training
- **Code Review Practice**: Identify vulnerabilities in sample code
- **Secure Coding Education**: Learn about common security mistakes
- **Developer Training**: Understand security implications

### Academic Applications
- **Computer Security Courses**: Hands-on vulnerability analysis
- **Software Engineering**: Security in development lifecycle
- **Cybersecurity Programs**: Practical security assessment

### Professional Development
- **Code Auditing**: Systematic security review process
- **Security Assessment**: Identify risks in legacy code
- **Compliance Checking**: Verify security standards

## ⚠️ Important Notes

### Educational Purpose
This tool is designed for **educational and training purposes only**:
- Results may include false positives
- Should be validated by security experts
- Not a substitute for professional security assessment
- Use only on code you own or have permission to analyze

### Limitations
- Static analysis only (no runtime analysis)
- Pattern-based detection (may miss complex vulnerabilities)
- Language-specific rules (some languages have limited coverage)
- No network or dynamic analysis capabilities

### Best Practices
- Always validate findings manually
- Use in safe, controlled environments
- Combine with other security tools
- Regular updates to security rules

## 🛠️ Technical Details

### Dependencies
- **Streamlit**: Web application framework
- **Plotly**: Interactive visualizations
- **Pandas**: Data manipulation and analysis
- **Pathlib**: File system operations

### Architecture
- **Modular Design**: Separate analysis engine and web interface
- **Temporary File Handling**: Safe processing of uploaded code
- **Real-time Analysis**: Immediate feedback on code submission
- **Responsive UI**: Works on desktop and mobile devices

### Performance
- **Fast Analysis**: Efficient pattern matching
- **Memory Efficient**: Temporary file cleanup
- **Scalable**: Handles large code files
- **Interactive**: Real-time filtering and sorting

## 📖 Getting Help

### In-App Help
- Severity level explanations in sidebar
- Supported languages reference
- Interactive tooltips and help text

### Troubleshooting
- Ensure virtual environment is activated
- Check file permissions for uploads
- Verify supported file types
- Review browser console for errors

---

**🔒 Remember: This is an educational tool. Always follow responsible disclosure and ethical guidelines when analyzing code.**
