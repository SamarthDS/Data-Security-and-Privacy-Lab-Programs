# File Security Scanner - Streamlit Application

A comprehensive web-based file security analysis tool built with Streamlit. This educational tool performs static analysis on uploaded files to identify potential security threats and vulnerabilities.

## Features

### 🔐 Core Security Analysis
- **File Hash Generation**: MD5, SHA1, SHA256 checksums for file identification
- **Entropy Analysis**: Detect packed, encrypted, or obfuscated content
- **String Pattern Matching**: Search for suspicious strings and URLs
- **Risk Assessment**: Automated scoring based on multiple factors

### 📄 File Type Support
- **Windows Executables**: PE file analysis (imports, sections, entropy)
- **Office Documents**: VBA macro detection and analysis
- **PDF Files**: Basic structure analysis
- **Scripts**: Python, JavaScript, PowerShell analysis
- **Any File Type**: Universal string and pattern analysis

### 🛡️ Advanced Features
- **VirusTotal Integration**: Optional threat intelligence lookup
- **Interactive Visualizations**: Risk gauges, entropy charts, findings distribution
- **Detailed Reporting**: Comprehensive analysis with explanations
- **Export Capabilities**: JSON and CSV report generation
- **Educational Content**: Attack type identification and explanations

## Installation

### Prerequisites
- Python 3.7+
- Virtual environment (recommended)

### Required Packages
```bash
pip install streamlit plotly pandas python-magic pefile oletools requests
```

### Optional Dependencies
- **python-magic**: Enhanced file type detection
- **pefile**: Windows PE file analysis
- **oletools**: Office document macro analysis
- **requests**: VirusTotal API integration

## Usage

### Running the Application
```bash
streamlit run streamlit_file_scanner.py
```

The application will be available at `http://localhost:8503`

### Using the Scanner

1. **Upload File**: Use the file uploader to select any file for analysis
2. **Configure Options**: 
   - Enter VirusTotal API key (optional)
   - Toggle display options in the sidebar
3. **Analyze**: Click "Start Analysis" to begin scanning
4. **Review Results**: Examine the comprehensive security report
5. **Export**: Download detailed reports in JSON or CSV format

### VirusTotal Integration
To enable VirusTotal lookups:
1. Sign up for a free VirusTotal account
2. Get your API key from the VirusTotal console
3. Enter the API key in the sidebar

## Security Analysis Components

### Risk Scoring
The tool uses a point-based risk assessment system:
- **LOW (0-3 points)**: Minimal security concerns
- **MEDIUM (4-7 points)**: Some suspicious patterns detected
- **HIGH (8+ points)**: Multiple high-risk indicators found

### Detection Categories

#### High-Risk Indicators (2-5 points each)
- Hardcoded credentials or secrets
- Dynamic code execution (eval, exec)
- Shell command injection patterns
- Suspicious API imports
- VirusTotal detections

#### Medium-Risk Indicators (1-2 points each)
- Weak cryptographic functions
- Insecure file permissions
- Base64 encoded secrets
- High entropy content

#### Low-Risk Indicators (1 point each)
- Hardcoded URLs
- Extension mismatches
- Unusual file structures

### File Type Analysis

#### PE Files (Windows Executables)
- Import table analysis
- Section entropy calculation
- Suspicious API detection
- Packing/obfuscation indicators

#### Office Documents
- VBA macro detection
- Auto-execution capability
- Suspicious macro patterns
- External reference analysis

## Educational Use Cases

### Malware Analysis Training
- Safe static analysis without execution
- Pattern recognition learning
- Risk assessment methodology
- Threat categorization

### Security Awareness
- Understanding file-based threats
- Recognition of suspicious patterns
- Best practices for file handling
- Incident response training

### Penetration Testing
- Pre-analysis of suspicious files
- Evidence documentation
- Risk prioritization
- Compliance checking

## Sample Test Files

The application includes test files for demonstration:
- `test_vulnerable_file.py`: Contains multiple security vulnerabilities
- Upload this file to see how the scanner identifies various threats

## Security Notice

⚠️ **Important Security Information**

- This tool performs **STATIC ANALYSIS ONLY** - files are never executed
- Analysis is based on heuristics and patterns, not behavioral analysis
- Results are for educational purposes and should be verified with professional tools
- Only analyze files you have permission to examine
- Do not upload sensitive or confidential files to public instances

## Technical Architecture

### Core Components
- **scanner_module.py**: Core file analysis engine
- **streamlit_file_scanner.py**: Web interface and visualization
- **6.py**: Original command-line scanner

### Dependencies
- **Streamlit**: Web application framework
- **Plotly**: Interactive visualizations
- **pandas**: Data manipulation and export
- **python-magic**: File type detection
- **pefile**: PE file analysis
- **oletools**: Office document analysis
- **requests**: HTTP client for VirusTotal API

## API Integration

### VirusTotal API
The tool supports VirusTotal API v3 for enhanced threat intelligence:
- File hash lookup
- Detection statistics
- Threat categorization
- Historical analysis data

### Rate Limiting
- Free tier: 4 requests per minute
- Automatic error handling for rate limits
- Optional API key validation

## Visualization Features

### Interactive Charts
- **Risk Gauge**: Visual risk level indicator
- **Entropy Analysis**: File randomness visualization
- **Findings Distribution**: Categorized threat overview
- **Detection Timeline**: Historical analysis data

### Export Formats
- **JSON Report**: Complete analysis data
- **CSV Summary**: Tabular overview
- **Timestamps**: Analysis metadata
- **Hash Values**: File identification

## Limitations

### Analysis Scope
- Static analysis only (no code execution)
- Heuristic-based detection (may have false positives)
- Limited to known patterns and signatures
- No behavioral analysis capabilities

### File Size Limits
- Streamlit default: 200MB file uploads
- Memory usage scales with file size
- Processing time varies by file type and size

### Dependencies
- Some features require optional libraries
- VirusTotal requires internet connectivity
- Analysis quality depends on available tools

## Contributing

This is an educational tool. Contributions are welcome for:
- Additional file format support
- New detection patterns
- Visualization improvements
- Documentation updates

## License

Educational use only. Not for commercial purposes.

## Support

For issues or questions:
1. Check the console output for error messages
2. Verify all dependencies are installed
3. Ensure proper file permissions
4. Test with known good/bad files

---

**Disclaimer**: This tool is for educational and defensive security purposes only. The authors are not responsible for any misuse of this software.
