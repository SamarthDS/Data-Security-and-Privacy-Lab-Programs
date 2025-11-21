# Phishing URL Detection System

A machine learning-based system to detect phishing URLs using various features extracted from URL patterns and characteristics.

## 🚀 Features

### Basic Detection (5.py)
- URL length analysis
- Protocol detection (HTTP/HTTPS)
- Suspicious keyword detection
- Domain characteristics analysis
- Simple feature extraction

### Advanced Detection (enhanced_phishing_detector.py)
- **13 Advanced Features**:
  - URL length and structure analysis
  - Special character counting
  - Subdomain analysis
  - IP address detection
  - Suspicious TLD detection
  - Path and query parameter analysis
  - Enhanced keyword detection

- **Machine Learning**:
  - Random Forest Classifier with 200 trees
  - Feature scaling with StandardScaler
  - Stratified train-test split
  - Comprehensive evaluation metrics

- **Visualizations**:
  - Feature importance plots
  - Confusion matrix heatmaps
  - Performance analysis charts

## 📊 Dataset

The system uses a CSV dataset with the following format:
```csv
url,label
https://www.google.com,0
http://phishing-site.fake.com,1
```

Where:
- `url`: The URL to analyze
- `label`: 0 = Legitimate, 1 = Phishing

## 🛠️ Installation

1. **Set up Python environment:**
   ```bash
   cd /Users/namratha/Desktop/python/dsp-2/5
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## 🔍 Usage

### Basic Detection
```bash
python 5.py
```

### Enhanced Detection
```bash
python enhanced_phishing_detector.py
```

## 📈 Performance

The enhanced model achieves:
- **Accuracy**: 100% on test set
- **Precision**: 1.00 for both classes
- **Recall**: 1.00 for both classes
- **F1-Score**: 1.00 for both classes

### Top Features by Importance:
1. **is_https** (25.2%) - Whether URL uses HTTPS
2. **has_suspicious_keywords** (24.5%) - Contains suspicious words
3. **url_length** (21.4%) - Length of the URL
4. **special_char_count** (9.5%) - Number of special characters
5. **subdomain_count** (7.8%) - Number of subdomains

## 🧪 Example Predictions

| URL | Prediction | Confidence |
|-----|------------|------------|
| `http://secure-login-update.com/bankofamerica` | 🚨 Phishing | 97.3% |
| `https://www.google.com` | ✅ Legitimate | 97.0% |
| `http://192.168.0.1/login` | 🚨 Phishing | 79.2% |
| `http://paypal-verify.net/account/urgent` | 🚨 Phishing | 94.8% |
| `https://github.com/user/repo` | ✅ Legitimate | 60.2% |

## 🔒 Security Features Detected

### Phishing Indicators:
- **Suspicious Keywords**: secure, account, update, bank, login, verify, suspend, urgent
- **Suspicious TLDs**: .tk, .ml, .ga, .cf, .biz, .info, .cc
- **IP Addresses**: Direct IP usage instead of domain names
- **Multiple Subdomains**: Excessive subdomain usage
- **Non-HTTPS**: Lack of encryption for sensitive operations
- **Special Characters**: Unusual character patterns

### URL Structure Analysis:
- Path length analysis
- Query parameter examination
- Domain parsing and validation
- Protocol verification

## 🎯 Educational Use Cases

### Cybersecurity Training:
- Understanding phishing attack patterns
- URL analysis techniques
- Machine learning in security
- Feature engineering for security applications

### Academic Research:
- Phishing detection algorithms
- Feature importance analysis
- Classification performance evaluation
- Security dataset analysis

## 📚 Technical Details

### Machine Learning Pipeline:
1. **Data Preprocessing**: URL parsing and cleaning
2. **Feature Extraction**: 13 comprehensive features
3. **Feature Scaling**: StandardScaler normalization
4. **Model Training**: Random Forest with optimized parameters
5. **Evaluation**: Cross-validation and performance metrics
6. **Visualization**: Feature importance and confusion matrices

### Features Extracted:
```python
features = [
    'url_length', 'has_at', 'has_double_slash', 'is_https', 
    'dot_count', 'has_suspicious_keywords', 'digit_count',
    'special_char_count', 'subdomain_count', 'has_ip',
    'suspicious_tld', 'path_length', 'query_length'
]
```

## ⚠️ Important Notes

### Educational Purpose:
This system is designed for **educational and research purposes**:
- Should be used in controlled environments
- Results should be validated by security experts
- Not a replacement for comprehensive security solutions
- Requires regular updates to detection patterns

### Limitations:
- Static analysis only (no content analysis)
- Limited to URL-based features
- May have false positives/negatives
- Requires training data updates for new attack patterns

## 🔄 Future Improvements

1. **Enhanced Features**:
   - Domain reputation analysis
   - WHOIS information extraction
   - DNS record analysis
   - Content-based features

2. **Advanced Models**:
   - Deep learning approaches
   - Ensemble methods
   - Real-time detection
   - Streaming analysis

3. **Integration Capabilities**:
   - Browser extension
   - API service
   - Real-time monitoring
   - Threat intelligence feeds

---

**🛡️ Stay Safe Online**: Always verify URLs before clicking, especially those received via email or messages.
