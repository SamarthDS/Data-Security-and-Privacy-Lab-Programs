"""
Vulnerability Analyzer - Streamlit Web Application

An interactive web interface for the educational vulnerability analysis tool.
Features:
- File upload and text input for code analysis
- Interactive vulnerability report display
- Filtering and sorting capabilities
- Export functionality
- Detailed explanations and remediation suggestions
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import tempfile
import os
from pathlib import Path
import json
from datetime import datetime
import base64

# Import the vulnerability analyzer
import importlib.util
import sys
from pathlib import Path

# Get the absolute path to the vulnerability analyzer
current_dir = Path(__file__).parent
vuln_analyzer_path = current_dir / "4.py"

try:
    spec = importlib.util.spec_from_file_location("vuln_analyzer", str(vuln_analyzer_path))
    vuln_analyzer = importlib.util.module_from_spec(spec)
    sys.modules["vuln_analyzer"] = vuln_analyzer
    spec.loader.exec_module(vuln_analyzer)
    print(f"✅ Successfully loaded vulnerability analyzer from {vuln_analyzer_path}")
except Exception as e:
    print(f"❌ Error loading vulnerability analyzer: {str(e)}")
    st.error(f"Failed to load vulnerability analyzer: {str(e)}")
    st.stop()

def analyze_code(code_content, filename="uploaded_file.py"):
    """Analyze code content using the vulnerability analyzer."""
    if not code_content or not code_content.strip():
        st.error("❌ No code content provided!")
        return []
    
    # Create a temporary file
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp_file:
            tmp_file.write(code_content)
            tmp_path = Path(tmp_file.name)
    except Exception as e:
        st.error(f"❌ Error creating temporary file: {str(e)}")
        return []
    
    try:
        # Analyze the temporary file
        findings = vuln_analyzer.scan_file(tmp_path)
        
        # Update file paths to show the original filename
        for finding in findings:
            finding['file'] = filename
        
        st.success(f"✅ Analysis complete! Found {len(findings)} potential issues.")
        return findings
    except Exception as e:
        st.error(f"❌ Error during analysis: {str(e)}")
        return []
    finally:
        # Clean up temporary file
        try:
            os.unlink(tmp_path)
        except:
            pass

def create_severity_chart(findings_df):
    """Create a pie chart showing severity distribution."""
    if findings_df.empty:
        return go.Figure()
    
    severity_counts = findings_df['severity'].value_counts()
    colors = {'HIGH': '#ff4444', 'MEDIUM': '#ff8800', 'LOW': '#ffaa00'}
    
    fig = go.Figure(data=[go.Pie(
        labels=severity_counts.index,
        values=severity_counts.values,
        marker=dict(colors=[colors.get(sev, '#cccccc') for sev in severity_counts.index]),
        textinfo='label+percent+value',
        hovertemplate='%{label}<br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
    )])
    
    fig.update_layout(
        title="Vulnerability Distribution by Severity",
        height=400
    )
    
    return fig

def create_rule_chart(findings_df):
    """Create a horizontal bar chart showing vulnerabilities by rule."""
    if findings_df.empty:
        return go.Figure()
    
    rule_counts = findings_df['rule_name'].value_counts().head(10)
    
    fig = go.Figure(data=[go.Bar(
        x=rule_counts.values,
        y=rule_counts.index,
        orientation='h',
        marker_color='lightblue'
    )])
    
    fig.update_layout(
        title="Top 10 Vulnerability Types",
        xaxis_title="Count",
        yaxis_title="Vulnerability Type",
        height=400
    )
    
    return fig

def create_line_chart_by_line(findings_df):
    """Create a line chart showing vulnerabilities by line number."""
    if findings_df.empty:
        return go.Figure()
    
    line_counts = findings_df['line'].value_counts().sort_index()
    
    fig = go.Figure(data=[go.Scatter(
        x=line_counts.index,
        y=line_counts.values,
        mode='markers+lines',
        marker=dict(size=8, color='red'),
        line=dict(color='red', width=2)
    )])
    
    fig.update_layout(
        title="Vulnerability Distribution by Line Number",
        xaxis_title="Line Number",
        yaxis_title="Number of Issues",
        height=400
    )
    
    return fig

def get_severity_color(severity):
    """Get color for severity badge."""
    colors = {
        'HIGH': '#ff4444',
        'MEDIUM': '#ff8800',
        'LOW': '#ffaa00'
    }
    return colors.get(severity, '#cccccc')

def display_findings(findings_df, show_details=True):
    """Display findings in an organized way."""
    if findings_df.empty:
        st.success("🎉 No security issues found!")
        return
    
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Issues", len(findings_df))
    with col2:
        high_count = len(findings_df[findings_df['severity'] == 'HIGH'])
        st.metric("High Severity", high_count, delta=None if high_count == 0 else "⚠️")
    with col3:
        medium_count = len(findings_df[findings_df['severity'] == 'MEDIUM'])
        st.metric("Medium Severity", medium_count)
    with col4:
        low_count = len(findings_df[findings_df['severity'] == 'LOW'])
        st.metric("Low Severity", low_count)
    
    # Filters
    st.subheader("🔍 Filter Results")
    col1, col2 = st.columns(2)
    
    with col1:
        severity_filter = st.multiselect(
            "Filter by Severity",
            options=['HIGH', 'MEDIUM', 'LOW'],
            default=['HIGH', 'MEDIUM', 'LOW']
        )
    
    with col2:
        rule_filter = st.multiselect(
            "Filter by Rule Type",
            options=findings_df['rule_name'].unique(),
            default=findings_df['rule_name'].unique()
        )
    
    # Apply filters
    filtered_df = findings_df[
        (findings_df['severity'].isin(severity_filter)) &
        (findings_df['rule_name'].isin(rule_filter))
    ]
    
    if filtered_df.empty:
        st.warning("No results match the selected filters.")
        return
    
    # Display filtered results
    st.subheader(f"📋 Security Issues ({len(filtered_df)} found)")
    
    # Sort options
    sort_by = st.selectbox(
        "Sort by",
        options=['Severity', 'Line Number', 'Rule Type'],
        index=0
    )
    
    if sort_by == 'Severity':
        severity_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        filtered_df = filtered_df.sort_values('severity', key=lambda x: x.map(severity_order))
    elif sort_by == 'Line Number':
        filtered_df = filtered_df.sort_values('line')
    else:  # Rule Type
        filtered_df = filtered_df.sort_values('rule_name')
    
    # Display issues
    for idx, finding in filtered_df.iterrows():
        with st.expander(
            f"🚨 {finding['rule_name']} (Line {finding['line']}) - {finding['severity']}",
            expanded=False
        ):
            col1, col2 = st.columns([3, 1])
            
            with col1:
                st.markdown(f"**File:** `{finding['file']}`")
                st.markdown(f"**Line:** {finding['line']}")
                st.code(finding['snippet'], language='python')
                
                st.markdown("**🔍 Why this is a problem:**")
                st.write(finding['explanation'])
                
                st.markdown("**💡 How to fix it:**")
                st.write(finding['suggestion'])
            
            with col2:
                severity_color = get_severity_color(finding['severity'])
                st.markdown(
                    f"<div style='background-color: {severity_color}; color: white; padding: 10px; "
                    f"border-radius: 5px; text-align: center; font-weight: bold;'>"
                    f"{finding['severity']}</div>",
                    unsafe_allow_html=True
                )

def create_download_link(findings, filename="vulnerability_report.json"):
    """Create a download link for the findings."""
    report = {
        "generated_at": datetime.now().isoformat() + "Z",
        "findings": findings,
        "summary": vuln_analyzer.summarise_findings(findings)
    }
    
    json_string = json.dumps(report, indent=2)
    b64 = base64.b64encode(json_string.encode()).decode()
    href = f'<a href="data:file/json;base64,{b64}" download="{filename}">📥 Download Report (JSON)</a>'
    return href

def main():
    st.set_page_config(
        page_title="Vulnerability Analyzer",
        page_icon="🔒",
        layout="wide"
    )
    
    # Header
    st.title("🔒 Vulnerability Analyzer")
    st.markdown("**Educational Security Code Analysis Tool**")
    st.markdown("Identify common security vulnerabilities in your code for learning and training purposes.")
    
    # Sidebar
    st.sidebar.header("📂 Input Method")
    input_method = st.sidebar.radio(
        "Choose how to provide code:",
        ["Upload File", "Paste Code", "Load Example"]
    )
    
    findings = []
    filename = "code.py"
    
    # Input handling
    if input_method == "Upload File":
        st.sidebar.subheader("📁 Upload Code File")
        uploaded_file = st.sidebar.file_uploader(
            "Choose a file",
            type=['py', 'js', 'java', 'c', 'cpp', 'php', 'rb', 'go', 'rs', 'cs', 'sh'],
            help="Upload a source code file to analyze"
        )
        
        if uploaded_file:
            filename = uploaded_file.name
            code_content = str(uploaded_file.read(), "utf-8")
            st.sidebar.success(f"✅ Loaded {filename}")
            
            # Display file info
            st.subheader("📄 File Information")
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Filename", filename)
            with col2:
                st.metric("Size", f"{len(code_content)} chars")
            with col3:
                st.metric("Lines", len(code_content.splitlines()))
            
            # Show code preview
            with st.expander("👁️ Code Preview", expanded=False):
                st.code(code_content, language=Path(filename).suffix[1:] or 'python')
            
            # Analyze
            if st.button("🔍 Analyze Code", type="primary"):
                with st.spinner("Analyzing code for vulnerabilities..."):
                    findings = analyze_code(code_content, filename)
    
    elif input_method == "Paste Code":
        st.subheader("📝 Paste Your Code")
        
        # Language selection
        language = st.selectbox(
            "Select Language",
            options=['python', 'javascript', 'java', 'c', 'cpp', 'php', 'ruby', 'go', 'rust', 'csharp', 'shell'],
            index=0
        )
        filename = f"pasted_code.{language[:2] if language != 'python' else 'py'}"
        
        code_content = st.text_area(
            "Paste your code here:",
            height=300,
            placeholder="# Paste your code here...\nprint('Hello, World!')"
        )
        
        if code_content.strip():
            if st.button("🔍 Analyze Code", type="primary"):
                st.write(f"🔍 Debug: Analyzing {len(code_content)} characters of code...")
                with st.spinner("Analyzing code for vulnerabilities..."):
                    findings = analyze_code(code_content, filename)
        else:
            st.warning("⚠️ Please enter some code to analyze.")
    
    else:  # Load Example
        st.subheader("📚 Example Vulnerable Code")
        
        examples = {
            "Hardcoded Secrets": '''
# Example with hardcoded secrets
API_KEY = "sk-1234567890abcdef"
password = "mypassword123"

def connect_to_api():
    return f"Connecting with key: {API_KEY}"
''',
            "SQL Injection": '''
# Example with SQL injection vulnerability
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable: string concatenation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()
''',
            "Command Injection": '''
# Example with command injection
import os
import subprocess

def backup_file(filename):
    # Vulnerable: shell=True with user input
    subprocess.run(f"cp {filename} backup/", shell=True)
    
def list_directory(path):
    # Vulnerable: direct system call
    os.system(f"ls {path}")
''',
            "Weak Cryptography": '''
# Example with weak cryptographic functions
import hashlib

def hash_password(password):
    # Vulnerable: MD5 is weak
    return hashlib.md5(password.encode()).hexdigest()

def generate_token():
    # Vulnerable: non-cryptographic random
    import random
    return str(random.randint(1000000, 9999999))
'''
        }
        
        example_choice = st.selectbox("Choose an example:", list(examples.keys()))
        code_content = examples[example_choice]
        filename = f"example_{example_choice.lower().replace(' ', '_')}.py"
        
        st.code(code_content, language='python')
        
        if st.button("🔍 Analyze Example", type="primary"):
            with st.spinner("Analyzing example code..."):
                findings = analyze_code(code_content, filename)
    
    # Display results
    if findings:
        findings_df = pd.DataFrame(findings)
        
        st.header("📊 Analysis Results")
        
        # Charts
        col1, col2 = st.columns(2)
        
        with col1:
            severity_chart = create_severity_chart(findings_df)
            st.plotly_chart(severity_chart, use_container_width=True)
        
        with col2:
            rule_chart = create_rule_chart(findings_df)
            st.plotly_chart(rule_chart, use_container_width=True)
        
        # Line distribution chart
        line_chart = create_line_chart_by_line(findings_df)
        st.plotly_chart(line_chart, use_container_width=True)
        
        # Display findings
        display_findings(findings_df)
        
        # Download report
        st.subheader("📥 Export Report")
        download_link = create_download_link(findings, f"vulnerability_report_{filename}.json")
        st.markdown(download_link, unsafe_allow_html=True)
        
        # Summary statistics
        with st.expander("📈 Detailed Statistics", expanded=False):
            summary = vuln_analyzer.summarise_findings(findings)
            
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("By Severity")
                st.json(summary['by_severity'])
            
            with col2:
                st.subheader("By Rule Type")
                st.json(summary['by_rule'])
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: gray;'>
        <p>⚠️ <strong>Educational Tool:</strong> This analyzer is for learning purposes only.<br>
        Results may include false positives and should be validated by security experts.</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Help section
    with st.sidebar:
        st.markdown("---")
        st.subheader("ℹ️ Help")
        
        with st.expander("About Severity Levels"):
            st.markdown("""
            **HIGH**: Critical security vulnerabilities that could lead to:
            - Remote code execution
            - Data breaches
            - System compromise
            
            **MEDIUM**: Important security issues:
            - Weak cryptography
            - Information disclosure
            - Privilege escalation risks
            
            **LOW**: Security best practice violations:
            - Hardcoded URLs
            - Minor configuration issues
            """)
        
        with st.expander("Supported Languages"):
            st.markdown("""
            - Python (.py)
            - JavaScript (.js)
            - Java (.java)
            - C/C++ (.c, .cpp)
            - PHP (.php)
            - Ruby (.rb)
            - Go (.go)
            - Rust (.rs)
            - C# (.cs)
            - Shell scripts (.sh)
            """)

if __name__ == "__main__":
    main()
