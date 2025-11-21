"""
File Security Scanner - Streamlit Web Application

A comprehensive web interface for analyzing files for potential security threats.
Features:
- File upload and analysis
- Static analysis without file execution
- Risk assessment and scoring
- Interactive visualizations
- Detailed reporting
- VirusTotal integration
- Educational security insights
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import os
import tempfile
import io
from datetime import datetime
import hashlib
import base64

# Import the file scanner
import sys
sys.path.append(os.path.dirname(__file__))
from pathlib import Path
import math
import mimetypes
import re

# Import the scanner module
from scanner_module import scan_file

# Check library availability
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    from oletools.olevba import VBA_Parser
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Page configuration
st.set_page_config(
    page_title="🔐 File Security Scanner",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        text-align: center;
        background: linear-gradient(90deg, #FF6B6B, #4ECDC4);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 2rem;
    }
    
    .risk-high {
        background-color: #ff4444;
        color: white;
        padding: 15px;
        border-radius: 10px;
        text-align: center;
        font-weight: bold;
        margin: 10px 0;
    }
    
    .risk-medium {
        background-color: #ff8800;
        color: white;
        padding: 15px;
        border-radius: 10px;
        text-align: center;
        font-weight: bold;
        margin: 10px 0;
    }
    
    .risk-low {
        background-color: #00cc44;
        color: white;
        padding: 15px;
        border-radius: 10px;
        text-align: center;
        font-weight: bold;
        margin: 10px 0;
    }
    
    .feature-box {
        background-color: #f0f2f6;
        padding: 15px;
        border-radius: 10px;
        border-left: 4px solid #4ECDC4;
        margin: 10px 0;
    }
    
    .warning-box {
        background-color: #fff3cd;
        border: 1px solid #ffeaa7;
        border-radius: 5px;
        padding: 15px;
        margin: 10px 0;
    }
    
    .hash-display {
        font-family: 'Courier New', monospace;
        font-size: 0.9em;
        background-color: #f8f9fa;
        padding: 10px;
        border-radius: 5px;
        word-break: break-all;
    }
</style>
""", unsafe_allow_html=True)

def create_risk_gauge(risk_level, risk_points):
    """Create a risk gauge visualization."""
    if risk_level == "HIGH":
        color = "red"
        value = min(100, risk_points * 10)
    elif risk_level == "MEDIUM":
        color = "orange"
        value = min(70, risk_points * 8)
    else:
        color = "green"
        value = min(30, risk_points * 5)
    
    fig = go.Figure(go.Indicator(
        mode = "gauge+number+delta",
        value = value,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': f"Risk Level: {risk_level}"},
        delta = {'reference': 50},
        gauge = {
            'axis': {'range': [None, 100]},
            'bar': {'color': color},
            'steps': [
                {'range': [0, 30], 'color': "lightgreen"},
                {'range': [30, 70], 'color': "yellow"},
                {'range': [70, 100], 'color': "lightcoral"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 80
            }
        }
    ))
    
    fig.update_layout(height=300)
    return fig

def create_entropy_chart(entropy):
    """Create entropy visualization."""
    fig = go.Figure(go.Bar(
        x=['File Entropy'],
        y=[entropy],
        marker_color='red' if entropy > 7.5 else 'orange' if entropy > 6 else 'green',
        text=[f'{entropy:.2f}'],
        textposition='outside'
    ))
    
    fig.add_hline(y=7.5, line_dash="dash", line_color="red", 
                  annotation_text="High Entropy Threshold (7.5)")
    
    fig.update_layout(
        title="File Entropy Analysis",
        yaxis_title="Entropy Value",
        yaxis_range=[0, 8],
        height=300
    )
    
    return fig

def create_findings_chart(findings):
    """Create visualization for file type findings."""
    if not findings:
        return go.Figure()
    
    # Categorize findings
    categories = {'Suspicious': 0, 'Warning': 0, 'Info': 0}
    
    for finding in findings:
        finding_lower = finding.lower()
        if any(word in finding_lower for word in ['suspicious', 'malware', 'dangerous']):
            categories['Suspicious'] += 1
        elif any(word in finding_lower for word in ['warning', 'unusual', 'odd']):
            categories['Warning'] += 1
        else:
            categories['Info'] += 1
    
    fig = px.pie(
        values=list(categories.values()),
        names=list(categories.keys()),
        title="Analysis Findings Distribution",
        color_discrete_map={'Suspicious': 'red', 'Warning': 'orange', 'Info': 'blue'}
    )
    
    return fig

def analyze_uploaded_file(uploaded_file, vt_api_key=None):
    """Analyze uploaded file and return results."""
    # Save uploaded file to temporary location
    with tempfile.NamedTemporaryFile(delete=False, suffix=uploaded_file.name) as tmp_file:
        tmp_file.write(uploaded_file.getvalue())
        tmp_path = tmp_file.name
    
    try:
        # Analyze the file
        report = scan_file(tmp_path, vt_api_key)
        report['filename'] = uploaded_file.name
        report['upload_size'] = len(uploaded_file.getvalue())
        return report
    finally:
        # Clean up temporary file
        try:
            os.unlink(tmp_path)
        except:
            pass

def display_file_info(report):
    """Display basic file information."""
    st.subheader("📄 File Information")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Filename", report.get('filename', 'Unknown'))
        st.metric("File Size", f"{report.get('size', 0):,} bytes")
    
    with col2:
        st.metric("MIME Type", report.get('mime', 'Unknown'))
        st.metric("Extension", report.get('ext', 'None'))
    
    with col3:
        st.metric("Entropy", f"{report.get('entropy_sample', 0):.2f}")
        st.metric("Risk Level", report.get('risk', 'Unknown'))

def display_hashes(report):
    """Display file hashes."""
    st.subheader("🔐 File Hashes")
    
    hashes = report.get('hashes', {})
    
    for hash_type, hash_value in hashes.items():
        st.markdown(f"**{hash_type.upper()}:**")
        st.markdown(f'<div class="hash-display">{hash_value}</div>', unsafe_allow_html=True)
        
        # Add copy button (using st.code for easy copying)
        with st.expander(f"Copy {hash_type.upper()} Hash"):
            st.code(hash_value)

def display_risk_assessment(report):
    """Display risk assessment and visualizations."""
    st.subheader("⚠️ Risk Assessment")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        # Risk gauge
        risk_gauge = create_risk_gauge(report.get('risk', 'LOW'), report.get('risk_points', 0))
        st.plotly_chart(risk_gauge, use_container_width=True)
    
    with col2:
        # Entropy chart
        entropy_chart = create_entropy_chart(report.get('entropy_sample', 0))
        st.plotly_chart(entropy_chart, use_container_width=True)
    
    # Risk details
    risk_level = report.get('risk', 'LOW')
    risk_points = report.get('risk_points', 0)
    
    risk_class = f"risk-{risk_level.lower()}"
    st.markdown(f"""
    <div class="{risk_class}">
        <h3>Risk Level: {risk_level}</h3>
        <p>Risk Points: {risk_points}/10+</p>
    </div>
    """, unsafe_allow_html=True)

def display_threats_and_warnings(report):
    """Display potential threats and warnings."""
    st.subheader("🚨 Security Analysis")
    
    # Warnings
    warnings = report.get('warnings', [])
    if warnings:
        st.error("**Warnings Detected:**")
        for warning in warnings:
            st.write(f"• {warning}")
    
    # Suspicious strings
    suspicious_strings = report.get('suspicious_strings', [])
    if suspicious_strings:
        st.warning("**Suspicious Strings Found:**")
        for string in suspicious_strings[:10]:  # Limit display
            st.write(f"• {string}")
        if len(suspicious_strings) > 10:
            st.write(f"... and {len(suspicious_strings) - 10} more")
    
    # URLs found
    urls = report.get('urls_found', [])
    if urls:
        st.info("**URLs Found in File:**")
        for url in urls[:10]:  # Limit display
            st.write(f"• {url}")
        if len(urls) > 10:
            st.write(f"... and {len(urls) - 10} more")
    
    # Type-specific findings
    type_findings = report.get('type_findings', [])
    if type_findings:
        st.subheader("🔍 Technical Analysis")
        
        # Create findings chart
        findings_chart = create_findings_chart(type_findings)
        if findings_chart.data:
            st.plotly_chart(findings_chart, use_container_width=True)
        
        st.write("**Detailed Findings:**")
        for finding in type_findings:
            # Color code findings based on severity
            if any(word in finding.lower() for word in ['suspicious', 'malware', 'high entropy']):
                st.error(f"🚨 {finding}")
            elif any(word in finding.lower() for word in ['warning', 'unusual', 'odd']):
                st.warning(f"⚠️ {finding}")
            else:
                st.info(f"ℹ️ {finding}")

def display_attack_types(report):
    """Display probable attack types."""
    st.subheader("🎯 Probable Attack Types")
    
    attacks = report.get('probable_attacks', [])
    
    if attacks:
        st.write("**If this file were malicious, it might be used for:**")
        
        attack_categories = {
            'Ransomware': '🔒',
            'Downloader': '⬇️',
            'Process injection': '💉',
            'Macro-based': '📄',
            'Phishing': '🎣',
            'Packed/obfuscated': '📦',
            'Information-stealer': '🕵️'
        }
        
        for attack in attacks:
            # Find matching category
            emoji = '⚠️'
            for category, cat_emoji in attack_categories.items():
                if category.lower() in attack.lower():
                    emoji = cat_emoji
                    break
            
            st.write(f"{emoji} **{attack}**")
    else:
        st.success("✅ No specific attack patterns identified")

def display_virustotal_info(report):
    """Display VirusTotal information if available."""
    vt_data = report.get('virustotal')
    
    if vt_data and isinstance(vt_data, dict) and 'data' in vt_data:
        st.subheader("🛡️ VirusTotal Analysis")
        
        try:
            attributes = vt_data['data']['attributes']
            stats = attributes.get('last_analysis_stats', {})
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Malicious", stats.get('malicious', 0))
            with col2:
                st.metric("Suspicious", stats.get('suspicious', 0))
            with col3:
                st.metric("Clean", stats.get('harmless', 0))
            
            # Detection timeline
            if 'last_analysis_date' in attributes:
                analysis_date = datetime.fromtimestamp(attributes['last_analysis_date'])
                st.write(f"**Last Analysis:** {analysis_date.strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Engine results (top detections)
            results = attributes.get('last_analysis_results', {})
            detections = [(engine, result) for engine, result in results.items() 
                         if result.get('category') in ['malicious', 'suspicious']]
            
            if detections:
                st.write("**Detection Results:**")
                for engine, result in detections[:10]:  # Show top 10
                    st.write(f"• **{engine}**: {result.get('result', 'Unknown')}")
                
                if len(detections) > 10:
                    st.write(f"... and {len(detections) - 10} more detections")
        
        except Exception as e:
            st.error(f"Error parsing VirusTotal data: {e}")
    
    elif vt_data and 'error' in vt_data:
        st.warning(f"VirusTotal lookup failed: {vt_data['error']}")

def export_report(report):
    """Provide report export functionality."""
    st.subheader("📥 Export Report")
    
    # Prepare report data
    export_data = {
        'analysis_timestamp': datetime.now().isoformat(),
        'file_info': {
            'filename': report.get('filename'),
            'size': report.get('size'),
            'mime_type': report.get('mime'),
            'extension': report.get('ext')
        },
        'hashes': report.get('hashes', {}),
        'risk_assessment': {
            'level': report.get('risk'),
            'points': report.get('risk_points'),
            'entropy': report.get('entropy_sample')
        },
        'findings': {
            'warnings': report.get('warnings', []),
            'suspicious_strings': report.get('suspicious_strings', []),
            'urls_found': report.get('urls_found', []),
            'type_findings': report.get('type_findings', []),
            'probable_attacks': report.get('probable_attacks', [])
        }
    }
    
    # Add VirusTotal data if available
    if report.get('virustotal'):
        export_data['virustotal'] = report['virustotal']
    
    # Convert to JSON
    json_report = json.dumps(export_data, indent=2)
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Download JSON
        st.download_button(
            label="📄 Download JSON Report",
            data=json_report,
            file_name=f"security_report_{report.get('filename', 'file')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )
    
    with col2:
        # Download CSV (simplified)
        csv_data = pd.DataFrame([{
            'Filename': report.get('filename'),
            'Size': report.get('size'),
            'MIME Type': report.get('mime'),
            'Extension': report.get('ext'),
            'Risk Level': report.get('risk'),
            'Risk Points': report.get('risk_points'),
            'Entropy': report.get('entropy_sample'),
            'Warnings Count': len(report.get('warnings', [])),
            'Suspicious Strings': len(report.get('suspicious_strings', [])),
            'URLs Found': len(report.get('urls_found', [])),
            'Analysis Date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }])
        
        st.download_button(
            label="📊 Download CSV Summary",
            data=csv_data.to_csv(index=False),
            file_name=f"security_summary_{report.get('filename', 'file')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

def main():
    # Header
    st.markdown('<div class="main-header">🔐 File Security Scanner</div>', unsafe_allow_html=True)
    
    st.markdown("""
    <div style='text-align: center; margin-bottom: 2rem;'>
        <p style='font-size: 1.2rem; color: #666;'>
            Advanced Static File Analysis for Security Assessment
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar
    st.sidebar.header("🛠️ Scanner Configuration")
    
    # VirusTotal API Key
    vt_api_key = st.sidebar.text_input(
        "VirusTotal API Key (Optional)",
        type="password",
        help="Enter your VirusTotal API key for enhanced threat intelligence"
    )
    
    # Analysis options
    st.sidebar.subheader("🔧 Analysis Options")
    
    show_hashes = st.sidebar.checkbox("Show File Hashes", value=True)
    show_technical = st.sidebar.checkbox("Show Technical Details", value=True)
    show_export = st.sidebar.checkbox("Enable Report Export", value=True)
    
    # Library status
    st.sidebar.subheader("📚 Library Status")
    st.sidebar.write(f"🔮 Magic: {'✅' if MAGIC_AVAILABLE else '❌'}")
    st.sidebar.write(f"📄 PE Analysis: {'✅' if PEFILE_AVAILABLE else '❌'}")
    st.sidebar.write(f"📋 Office Analysis: {'✅' if OLETOOLS_AVAILABLE else '❌'}")
    st.sidebar.write(f"🌐 VirusTotal: {'✅' if REQUESTS_AVAILABLE else '❌'}")
    
    # Main content
    st.header("📁 Upload File for Analysis")
    
    uploaded_file = st.file_uploader(
        "Choose a file to analyze",
        type=None,  # Accept all file types
        help="Upload any file for security analysis. The file will NOT be executed, only analyzed statically.",
        key="file_uploader"
    )
    
    if uploaded_file is not None:
        # File info
        st.success(f"✅ File uploaded: **{uploaded_file.name}** ({len(uploaded_file.getvalue()):,} bytes)")
        
        # Warning about analysis
        st.warning("""
        ⚠️ **Important Notes:**
        - This tool performs STATIC analysis only - files are NOT executed
        - Analysis is based on heuristics and patterns
        - Results are educational and should be verified with professional tools
        - Upload only files you have permission to analyze
        """)
        
        # Analyze button
        if st.button("🔍 Start Analysis", type="primary", key="analyze_button"):
            with st.spinner("🔄 Analyzing file... This may take a few moments."):
                try:
                    # Perform analysis
                    report = analyze_uploaded_file(uploaded_file, vt_api_key if vt_api_key else None)
                    
                    # Display results
                    st.success("✅ Analysis completed!")
                    
                    # Store report in session state for export
                    st.session_state.last_report = report
                    
                    # Display file info
                    display_file_info(report)
                    
                    # Display hashes
                    if show_hashes:
                        display_hashes(report)
                    
                    # Display risk assessment
                    display_risk_assessment(report)
                    
                    # Display threats and warnings
                    display_threats_and_warnings(report)
                    
                    # Display technical details
                    if show_technical:
                        display_attack_types(report)
                    
                    # Display VirusTotal info
                    if vt_api_key and report.get('virustotal'):
                        display_virustotal_info(report)
                    
                    # Export options
                    if show_export:
                        export_report(report)
                
                except Exception as e:
                    st.error(f"❌ Analysis failed: {str(e)}")
                    st.exception(e)
    
    else:
        # Show example/demo section
        st.info("""
        ### 📖 How to Use This Tool
        
        1. **Upload a File** - Use the file uploader above to select any file for analysis
        2. **Optional VirusTotal** - Enter your VirusTotal API key in the sidebar for enhanced threat intelligence
        3. **Configure Options** - Use the sidebar to customize what information is displayed
        4. **Analyze** - Click the "Start Analysis" button to begin the security assessment
        5. **Review Results** - Examine the risk assessment, findings, and recommendations
        6. **Export Report** - Download detailed reports in JSON or CSV format
        
        ### 🔐 What This Tool Analyzes
        
        - **File Hashes** - MD5, SHA1, SHA256 for file identification
        - **Entropy Analysis** - Detect packed or encrypted content
        - **String Analysis** - Search for suspicious patterns and URLs
        - **PE Analysis** - Windows executable analysis (imports, sections, etc.)
        - **Office Macros** - VBA macro detection in Office documents
        - **VirusTotal Integration** - Optional threat intelligence lookup
        - **Risk Scoring** - Automated risk assessment based on findings
        
        ### 🚨 Security Notice
        
        This tool is for educational and defensive purposes only. It performs static analysis
        without executing files, making it safe for malware analysis training.
        """)
        
        # Sample files section
        st.subheader("📄 Supported File Types")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            **Executables**
            - .exe (Windows executables)
            - .dll (Dynamic libraries)
            - .sys (System files)
            """)
        
        with col2:
            st.markdown("""
            **Documents**
            - .doc, .docx (Word)
            - .xls, .xlsx (Excel)
            - .ppt, .pptx (PowerPoint)
            - .pdf (PDF documents)
            """)
        
        with col3:
            st.markdown("""
            **Other Files**
            - Scripts (.py, .js, .ps1)
            - Archives (.zip, .rar)
            - Any text-based files
            - Binary files
            """)
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: gray;'>
        <p>🔐 <strong>File Security Scanner</strong> - Educational Static Analysis Tool</p>
        <p>⚠️ For educational and defensive security purposes only</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
