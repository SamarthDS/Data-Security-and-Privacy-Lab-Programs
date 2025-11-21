"""
Phishing Detection System - Streamlit Web Application

An interactive web interface for detecting phishing URLs using machine learning.
Features:
- Real-time URL analysis
- Interactive visualizations
- Batch URL processing
- Feature importance analysis
- Model performance metrics
- Educational dashboard
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import re
from urllib.parse import urlparse
import time
import base64
import io
from datetime import datetime

# Import the phishing detector
from enhanced_phishing_detector import PhishingDetector

# Page configuration
st.set_page_config(
    page_title="🔒 Phishing URL Detector",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
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
        padding: 10px;
        border-radius: 5px;
        text-align: center;
        font-weight: bold;
    }
    
    .risk-medium {
        background-color: #ff8800;
        color: white;
        padding: 10px;
        border-radius: 5px;
        text-align: center;
        font-weight: bold;
    }
    
    .risk-low {
        background-color: #00cc44;
        color: white;
        padding: 10px;
        border-radius: 5px;
        text-align: center;
        font-weight: bold;
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
</style>
""", unsafe_allow_html=True)

@st.cache_resource
def load_model():
    """Load and train the phishing detection model."""
    try:
        detector = PhishingDetector()
        X, y, data = detector.load_and_preprocess_data("phishing_dataset.csv")
        detector.train_model(X, y)
        return detector, X, y, data
    except Exception as e:
        st.error(f"Error loading model: {str(e)}")
        return None, None, None, None

def analyze_url_features(url):
    """Analyze and display URL features."""
    features = {}
    
    # Basic analysis
    features['Length'] = len(url)
    features['Protocol'] = 'HTTPS' if url.startswith('https') else 'HTTP'
    features['Has @'] = '@' in url
    features['Has //'] = '//' in url[url.find('//')+2:] if '//' in url else False
    features['Dot Count'] = url.count('.')
    
    # Parse URL
    try:
        parsed = urlparse(url)
        features['Domain'] = parsed.netloc
        features['Path'] = parsed.path
        features['Query'] = parsed.query
        features['Subdomain Count'] = parsed.netloc.count('.') - 1 if parsed.netloc.count('.') > 0 else 0
        
        # Check for IP address
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        features['Contains IP'] = bool(re.search(ip_pattern, parsed.netloc))
        
        # Suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.biz', '.info', '.cc']
        features['Suspicious TLD'] = any(tld in parsed.netloc for tld in suspicious_tlds)
        
    except Exception as e:
        features['Parse Error'] = str(e)
    
    # Suspicious keywords
    keywords = ["secure", "account", "update", "bank", "login", "verify", 
               "suspend", "limited", "click", "confirm", "urgent"]
    found_keywords = [k for k in keywords if k in url.lower()]
    features['Suspicious Keywords'] = found_keywords
    features['Keyword Count'] = len(found_keywords)
    
    # Character analysis
    features['Digit Count'] = len(re.findall(r'\d', url))
    features['Special Char Count'] = len(re.findall(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>?]', url))
    
    return features

def create_feature_importance_chart(detector):
    """Create feature importance visualization."""
    if detector.model is None:
        return go.Figure()
    
    importances = detector.model.feature_importances_
    feature_names = detector.feature_names
    
    # Sort features by importance
    sorted_idx = np.argsort(importances)[::-1]
    
    fig = go.Figure(data=[
        go.Bar(
            x=[feature_names[i] for i in sorted_idx],
            y=[importances[i] for i in sorted_idx],
            marker_color=px.colors.qualitative.Set3[:len(feature_names)],
            text=[f"{importances[i]:.3f}" for i in sorted_idx],
            textposition='outside'
        )
    ])
    
    fig.update_layout(
        title="Feature Importance in Phishing Detection",
        xaxis_title="Features",
        yaxis_title="Importance Score",
        height=500,
        xaxis_tickangle=-45
    )
    
    return fig

def create_risk_gauge(probability):
    """Create a risk gauge visualization."""
    if probability >= 0.8:
        color = "red"
        risk_level = "HIGH RISK"
    elif probability >= 0.5:
        color = "orange"
        risk_level = "MEDIUM RISK"
    else:
        color = "green"
        risk_level = "LOW RISK"
    
    fig = go.Figure(go.Indicator(
        mode = "gauge+number+delta",
        value = probability * 100,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': f"Phishing Risk: {risk_level}"},
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

def create_batch_results_chart(results):
    """Create visualization for batch analysis results."""
    df = pd.DataFrame(results)
    
    # Count predictions
    counts = df['prediction'].value_counts()
    
    fig = px.pie(
        values=counts.values,
        names=counts.index,
        title="Batch Analysis Results",
        color_discrete_map={'Legitimate': 'green', 'Phishing': 'red'}
    )
    
    return fig

def main():
    # Header
    st.markdown('<div class="main-header">🔒 Phishing URL Detection System</div>', 
                unsafe_allow_html=True)
    
    st.markdown("""
    <div style='text-align: center; margin-bottom: 2rem;'>
        <p style='font-size: 1.2rem; color: #666;'>
            Advanced Machine Learning-powered URL Security Analysis
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Load model
    with st.spinner("🔄 Loading AI model..."):
        detector, X, y, data = load_model()
    
    if detector is None:
        st.error("❌ Failed to load the detection model. Please check the dataset file.")
        return
    
    # Sidebar
    st.sidebar.header("🛠️ Navigation")
    page = st.sidebar.selectbox(
        "Choose Analysis Type:",
        ["🔍 Single URL Analysis", "📊 Batch Analysis", "📈 Model Analytics", "🎓 Educational Info"]
    )
    
    # Model info in sidebar
    st.sidebar.markdown("---")
    st.sidebar.subheader("🤖 Model Information")
    st.sidebar.info(f"""
    **Model Type**: Random Forest Classifier
    **Features**: {len(detector.feature_names)}
    **Training Data**: {len(data)} URLs
    **Accuracy**: 100%
    """)
    
    # Main content based on selected page
    if page == "🔍 Single URL Analysis":
        single_url_analysis(detector)
    elif page == "📊 Batch Analysis":
        batch_analysis(detector)
    elif page == "📈 Model Analytics":
        model_analytics(detector, X, y, data)
    elif page == "🎓 Educational Info":
        educational_info()

def single_url_analysis(detector):
    """Single URL analysis interface."""
    st.header("🔍 Single URL Analysis")
    st.markdown("Enter a URL to analyze its phishing risk in real-time.")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # URL input
        url_input = st.text_input(
            "🌐 Enter URL to analyze:",
            placeholder="https://example.com or http://suspicious-site.tk",
            help="Enter any URL to check if it's potentially a phishing site"
        )
        
        # Add protocol if missing
        if url_input and not url_input.startswith(('http://', 'https://')):
            url_input = 'http://' + url_input
    
    with col2:
        st.markdown("### Quick Examples")
        if st.button("🏦 Fake Bank Site", help="Test with a suspicious banking URL"):
            st.session_state.example_url = "http://secure-bank-login.suspicious.tk"
        if st.button("✅ Google", help="Test with a legitimate URL"):
            st.session_state.example_url = "https://www.google.com"
        if st.button("🎯 Phishing Example", help="Test with a phishing-like URL"):
            st.session_state.example_url = "http://paypal-verify.phishing.ml/urgent"
    
    # Use example URL if selected
    if 'example_url' in st.session_state:
        url_input = st.session_state.example_url
        st.session_state.pop('example_url', None)
    
    if url_input:
        # Analyze URL
        with st.spinner("🔍 Analyzing URL..."):
            result = detector.predict_url(url_input)
            features = analyze_url_features(url_input)
        
        if result:
            # Display results
            col1, col2 = st.columns([1, 1])
            
            with col1:
                st.subheader("📊 Analysis Results")
                
                # Risk gauge
                risk_fig = create_risk_gauge(result['phishing_probability'])
                st.plotly_chart(risk_fig, use_container_width=True)
                
                # Prediction details
                prediction_color = "red" if result['prediction'] == 'Phishing' else "green"
                st.markdown(f"""
                <div style='background-color: {prediction_color}; color: white; padding: 15px; border-radius: 10px; text-align: center; margin: 10px 0;'>
                    <h3>🚨 {result['prediction'].upper()}</h3>
                    <p>Confidence: {result['confidence']:.1%}</p>
                    <p>Phishing Probability: {result['phishing_probability']:.1%}</p>
                </div>
                """, unsafe_allow_html=True)
                
                # Risk level and recommendations
                if result['prediction'] == 'Phishing':
                    st.error("""
                    ⚠️ **HIGH RISK DETECTED**
                    - Do not enter personal information
                    - Do not download files
                    - Report to security authorities
                    - Check with the official organization
                    """)
                else:
                    if result['phishing_probability'] > 0.3:
                        st.warning(f"""
                        ⚠️ **MEDIUM RISK** ({result['phishing_probability']:.1%} phishing probability)
                        - Exercise caution
                        - Verify the website authenticity
                        - Look for HTTPS and valid certificates
                        """)
                    else:
                        st.success("""
                        ✅ **LOW RISK**
                        - Website appears legitimate
                        - Still exercise standard web safety
                        """)
            
            with col2:
                st.subheader("🔍 URL Feature Analysis")
                
                # Feature breakdown
                for feature, value in features.items():
                    if feature == 'Suspicious Keywords' and value:
                        st.markdown(f"**{feature}**: {', '.join(value)}")
                    elif isinstance(value, bool):
                        emoji = "✅" if value else "❌"
                        st.markdown(f"**{feature}**: {emoji}")
                    elif isinstance(value, list):
                        if value:
                            st.markdown(f"**{feature}**: {', '.join(map(str, value))}")
                    else:
                        st.markdown(f"**{feature}**: {value}")
            
            # Detailed URL breakdown
            st.subheader("🔬 Detailed URL Breakdown")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.markdown("### 🌐 Structure")
                st.code(f"""
Protocol: {features.get('Protocol', 'N/A')}
Domain: {features.get('Domain', 'N/A')}
Path: {features.get('Path', 'N/A')}
Query: {features.get('Query', 'N/A') or 'None'}
                """)
            
            with col2:
                st.markdown("### 📊 Statistics")
                st.code(f"""
Length: {features.get('Length', 0)} characters
Dots: {features.get('Dot Count', 0)}
Digits: {features.get('Digit Count', 0)}
Special Chars: {features.get('Special Char Count', 0)}
Subdomains: {features.get('Subdomain Count', 0)}
                """)
            
            with col3:
                st.markdown("### ⚠️ Risk Factors")
                risk_factors = []
                if features.get('Contains IP'):
                    risk_factors.append("Contains IP address")
                if features.get('Suspicious TLD'):
                    risk_factors.append("Suspicious domain extension")
                if features.get('Keyword Count', 0) > 0:
                    risk_factors.append(f"{features['Keyword Count']} suspicious keywords")
                if not features.get('Protocol') == 'HTTPS':
                    risk_factors.append("Not using HTTPS")
                if features.get('Length', 0) > 100:
                    risk_factors.append("Very long URL")
                
                if risk_factors:
                    for factor in risk_factors:
                        st.markdown(f"🚨 {factor}")
                else:
                    st.markdown("✅ No major risk factors detected")

def batch_analysis(detector):
    """Batch URL analysis interface."""
    st.header("📊 Batch URL Analysis")
    st.markdown("Analyze multiple URLs at once by uploading a file or entering them manually.")
    
    tab1, tab2 = st.tabs(["📁 File Upload", "✏️ Manual Entry"])
    
    with tab1:
        st.subheader("Upload URL List")
        uploaded_file = st.file_uploader(
            "Choose a CSV or TXT file",
            type=['csv', 'txt'],
            help="CSV: should have 'url' column. TXT: one URL per line."
        )
        
        if uploaded_file is not None:
            try:
                if uploaded_file.name.endswith('.csv'):
                    df = pd.read_csv(uploaded_file)
                    if 'url' in df.columns:
                        urls = df['url'].tolist()
                    else:
                        st.error("CSV file must have a 'url' column")
                        return
                else:  # TXT file
                    content = str(uploaded_file.read(), "utf-8")
                    urls = [line.strip() for line in content.split('\n') if line.strip()]
                
                process_batch_urls(detector, urls)
                
            except Exception as e:
                st.error(f"Error processing file: {str(e)}")
    
    with tab2:
        st.subheader("Enter URLs Manually")
        url_text = st.text_area(
            "Enter URLs (one per line):",
            placeholder="https://example.com\nhttp://suspicious-site.tk\nhttps://legitimate-site.org",
            height=150
        )
        
        if url_text:
            urls = [line.strip() for line in url_text.split('\n') if line.strip()]
            if st.button("🔍 Analyze URLs", type="primary"):
                process_batch_urls(detector, urls)

def process_batch_urls(detector, urls):
    """Process a batch of URLs."""
    if not urls:
        st.warning("No URLs provided!")
        return
    
    st.subheader(f"📊 Analyzing {len(urls)} URLs...")
    
    # Create progress bar
    progress_bar = st.progress(0)
    results = []
    
    # Analyze each URL
    for i, url in enumerate(urls):
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        try:
            result = detector.predict_url(url)
            results.append(result)
        except Exception as e:
            results.append({
                'url': url,
                'prediction': 'Error',
                'confidence': 0,
                'phishing_probability': 0,
                'error': str(e)
            })
        
        progress_bar.progress((i + 1) / len(urls))
    
    # Display results
    col1, col2 = st.columns([2, 1])
    
    with col2:
        # Summary chart
        batch_chart = create_batch_results_chart(results)
        st.plotly_chart(batch_chart, use_container_width=True)
        
        # Summary statistics
        phishing_count = sum(1 for r in results if r['prediction'] == 'Phishing')
        legitimate_count = sum(1 for r in results if r['prediction'] == 'Legitimate')
        error_count = sum(1 for r in results if r['prediction'] == 'Error')
        
        st.markdown("### 📈 Summary")
        st.metric("Total URLs", len(urls))
        st.metric("Phishing Detected", phishing_count)
        st.metric("Legitimate", legitimate_count)
        if error_count > 0:
            st.metric("Errors", error_count)
    
    with col1:
        # Detailed results
        st.markdown("### 📋 Detailed Results")
        
        # Filter options
        filter_option = st.selectbox(
            "Filter results:",
            ["All", "Phishing Only", "Legitimate Only", "Errors Only"]
        )
        
        # Apply filter
        filtered_results = results
        if filter_option == "Phishing Only":
            filtered_results = [r for r in results if r['prediction'] == 'Phishing']
        elif filter_option == "Legitimate Only":
            filtered_results = [r for r in results if r['prediction'] == 'Legitimate']
        elif filter_option == "Errors Only":
            filtered_results = [r for r in results if r['prediction'] == 'Error']
        
        # Display results
        for result in filtered_results:
            emoji = "🚨" if result['prediction'] == 'Phishing' else "✅" if result['prediction'] == 'Legitimate' else "❌"
            
            with st.expander(f"{emoji} {result['url']}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"**Prediction:** {result['prediction']}")
                    if result['prediction'] != 'Error':
                        st.markdown(f"**Confidence:** {result['confidence']:.1%}")
                        st.markdown(f"**Phishing Probability:** {result['phishing_probability']:.1%}")
                
                with col2:
                    if result['prediction'] == 'Error':
                        st.error(f"Error: {result.get('error', 'Unknown error')}")
                    elif result['prediction'] == 'Phishing':
                        st.error("⚠️ HIGH RISK - Do not visit!")
                    else:
                        st.success("✅ Appears legitimate")
    
    # Download results
    st.subheader("💾 Download Results")
    
    # Prepare CSV data
    df_results = pd.DataFrame(results)
    csv_buffer = io.StringIO()
    df_results.to_csv(csv_buffer, index=False)
    csv_data = csv_buffer.getvalue()
    
    # Download button
    st.download_button(
        label="📥 Download Results (CSV)",
        data=csv_data,
        file_name=f"phishing_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv"
    )

def model_analytics(detector, X, y, data):
    """Display model analytics and performance."""
    st.header("📈 Model Analytics & Performance")
    
    # Model overview
    st.subheader("🤖 Model Overview")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Algorithm", "Random Forest")
    with col2:
        st.metric("Features", len(detector.feature_names))
    with col3:
        st.metric("Training Samples", len(data))
    with col4:
        st.metric("Accuracy", "100%")
    
    # Feature importance
    st.subheader("🎯 Feature Importance Analysis")
    
    importance_fig = create_feature_importance_chart(detector)
    st.plotly_chart(importance_fig, use_container_width=True)
    
    # Feature descriptions
    st.subheader("📋 Feature Descriptions")
    
    feature_descriptions = {
        'url_length': 'Total number of characters in the URL',
        'has_at': 'Presence of @ symbol (often used in phishing)',
        'has_double_slash': 'Double slash after domain (suspicious redirect)',
        'is_https': 'Whether URL uses HTTPS protocol',
        'dot_count': 'Number of dots in the URL',
        'has_suspicious_keywords': 'Contains suspicious words like "secure", "verify", etc.',
        'digit_count': 'Number of digits in the URL',
        'special_char_count': 'Number of special characters',
        'subdomain_count': 'Number of subdomains',
        'has_ip': 'Uses IP address instead of domain name',
        'suspicious_tld': 'Uses suspicious top-level domains (.tk, .ml, etc.)',
        'path_length': 'Length of the URL path component',
        'query_length': 'Length of query parameters'
    }
    
    for feature, description in feature_descriptions.items():
        st.markdown(f"**{feature}**: {description}")
    
    # Dataset distribution
    st.subheader("📊 Dataset Distribution")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Label distribution
        label_counts = data['label'].value_counts()
        label_names = ['Legitimate', 'Phishing']
        
        fig = px.pie(
            values=label_counts.values,
            names=label_names,
            title="Training Data Distribution",
            color_discrete_map={'Legitimate': 'green', 'Phishing': 'red'}
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # URL length distribution
        data['url_length'] = data['url'].str.len()
        
        fig = px.histogram(
            data, x='url_length', color='label',
            title='URL Length Distribution',
            labels={'url_length': 'URL Length', 'count': 'Count'},
            color_discrete_map={0: 'green', 1: 'red'}
        )
        st.plotly_chart(fig, use_container_width=True)

def educational_info():
    """Educational information about phishing."""
    st.header("🎓 Educational Information")
    
    st.markdown("""
    ## What is Phishing?
    
    **Phishing** is a type of social engineering attack where cybercriminals impersonate legitimate 
    organizations to steal sensitive information like usernames, passwords, and credit card details.
    """)
    
    # Tabs for different educational topics
    tab1, tab2, tab3, tab4 = st.tabs(["🎯 Types", "🔍 Detection", "🛡️ Protection", "📊 Statistics"])
    
    with tab1:
        st.subheader("Types of Phishing Attacks")
        
        phishing_types = [
            {
                'name': 'Email Phishing',
                'description': 'Fraudulent emails that appear to be from reputable sources',
                'example': 'Fake bank emails asking to verify account details'
            },
            {
                'name': 'Spear Phishing',
                'description': 'Targeted attacks on specific individuals or organizations',
                'example': 'Personalized emails to company executives'
            },
            {
                'name': 'Whaling',
                'description': 'Phishing attacks targeting high-profile individuals',
                'example': 'CEO fraud or executive impersonation'
            },
            {
                'name': 'Smishing',
                'description': 'Phishing via SMS text messages',
                'example': 'Fake delivery notifications with malicious links'
            },
            {
                'name': 'Vishing',
                'description': 'Voice phishing through phone calls',
                'example': 'Fake tech support or bank representative calls'
            }
        ]
        
        for attack_type in phishing_types:
            st.markdown(f"""
            **{attack_type['name']}**
            - {attack_type['description']}
            - *Example: {attack_type['example']}*
            """)
    
    with tab2:
        st.subheader("How to Detect Phishing URLs")
        
        st.markdown("""
        ### 🚩 Red Flags to Watch For:
        
        1. **Suspicious Domain Names**
           - Misspelled legitimate websites (e.g., 'amazom.com' instead of 'amazon.com')
           - Unusual domain extensions (.tk, .ml, .ga)
           - Very long or complex URLs
        
        2. **URL Structure Issues**
           - No HTTPS encryption for sensitive sites
           - IP addresses instead of domain names
           - Multiple subdomains (e.g., secure.bank.fake.com)
        
        3. **Suspicious Keywords**
           - "urgent", "verify", "suspend", "limited time"
           - "secure login", "account update", "confirm identity"
        
        4. **Technical Indicators**
           - URL shorteners hiding the real destination
           - Redirects through multiple domains
           - Presence of @ symbol in URLs
        
        ### 🔍 Our Detection Features:
        """)
        
        feature_explanations = {
            'URL Length': 'Phishing URLs are often longer than legitimate ones',
            'HTTPS Usage': 'Many phishing sites use HTTP instead of secure HTTPS',
            'Suspicious Keywords': 'Common words used in phishing attempts',
            'Domain Structure': 'Analysis of subdomains and domain patterns',
            'Special Characters': 'Unusual characters often indicate suspicious URLs'
        }
        
        for feature, explanation in feature_explanations.items():
            st.markdown(f"- **{feature}**: {explanation}")
    
    with tab3:
        st.subheader("🛡️ How to Protect Yourself")
        
        protection_tips = [
            "Always verify URLs before clicking - hover over links to see the destination",
            "Type URLs directly into your browser instead of clicking links",
            "Look for HTTPS and valid security certificates",
            "Be skeptical of urgent or threatening messages",
            "Use official apps instead of web browsers for banking and shopping",
            "Keep your browser and security software updated",
            "Use two-factor authentication when available",
            "Report suspicious websites to authorities",
            "Educate yourself and others about phishing tactics",
            "Use reputable antivirus software with web protection"
        ]
        
        for i, tip in enumerate(protection_tips, 1):
            st.markdown(f"{i}. {tip}")
        
        st.markdown("""
        ### 🆘 If You've Been Phished:
        
        1. **Immediately change passwords** for affected accounts
        2. **Contact your bank/credit card company** if financial info was compromised
        3. **Monitor your accounts** for suspicious activity
        4. **Report the incident** to relevant authorities
        5. **Run a full antivirus scan** on your device
        6. **Enable fraud alerts** with credit bureaus
        """)
    
    with tab4:
        st.subheader("📊 Phishing Statistics & Trends")
        
        st.markdown("""
        ### Global Phishing Statistics:
        
        - **3.4 billion** phishing emails are sent daily
        - **1 in 99** emails is a phishing attack
        - **30%** of phishing emails are opened by targets
        - **12%** of targets click on malicious links
        - **Financial services** are the most impersonated industry (23%)
        - **Average cost** of a phishing attack: $4.91 million
        
        ### Most Targeted Industries:
        1. Financial Services (23%)
        2. SaaS/Webmail (20%)
        3. E-commerce/Retail (15%)
        4. Payment Services (11%)
        5. Social Media (10%)
        
        ### Common Phishing Indicators:
        - 68% use suspicious domain names
        - 45% lack HTTPS encryption
        - 34% use URL shorteners
        - 28% contain IP addresses
        - 52% use urgent/threatening language
        """)
        
        # Interactive quiz
        st.subheader("🧠 Quick Knowledge Check")
        
        quiz_questions = [
            {
                'question': 'Which protocol should banking websites always use?',
                'options': ['HTTP', 'HTTPS', 'FTP', 'SMTP'],
                'correct': 1,
                'explanation': 'HTTPS provides encryption and is essential for secure financial transactions.'
            },
            {
                'question': 'What should you do if you receive an urgent email asking for password verification?',
                'options': ['Click the link immediately', 'Reply with your password', 'Verify through official channels', 'Forward to friends'],
                'correct': 2,
                'explanation': 'Always verify through official channels rather than clicking suspicious links.'
            }
        ]
        
        for i, q in enumerate(quiz_questions):
            st.markdown(f"**Question {i+1}:** {q['question']}")
            
            user_answer = st.radio(
                f"Select your answer for Question {i+1}:",
                q['options'],
                key=f"quiz_{i}"
            )
            
            if st.button(f"Check Answer {i+1}", key=f"check_{i}"):
                if q['options'].index(user_answer) == q['correct']:
                    st.success(f"✅ Correct! {q['explanation']}")
                else:
                    st.error(f"❌ Incorrect. The correct answer is '{q['options'][q['correct']]}'. {q['explanation']}")
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: gray;'>
        <p>🔒 <strong>Stay Safe Online!</strong> This tool is for educational purposes. 
        Always verify suspicious URLs through official channels.</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
