import pandas as pd
import numpy as np
import re
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import seaborn as sns
from urllib.parse import urlparse
import warnings
warnings.filterwarnings('ignore')

class PhishingDetector:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = [
            'url_length', 'has_at', 'has_double_slash', 'is_https', 
            'dot_count', 'has_suspicious_keywords', 'digit_count',
            'special_char_count', 'subdomain_count', 'has_ip',
            'suspicious_tld', 'path_length', 'query_length'
        ]
    
    def extract_advanced_features(self, url):
        """Extract comprehensive features from URL"""
        features = []
        
        # Basic features
        features.append(len(url))  # url_length
        features.append(1 if "@" in url else 0)  # has_at
        features.append(1 if "//" in url[url.find("//")+2:] else 0)  # has_double_slash
        features.append(1 if url.startswith("https") else 0)  # is_https
        features.append(url.count("."))  # dot_count
        
        # Suspicious keywords
        keywords = ["secure", "account", "update", "bank", "login", "verify", 
                   "suspend", "limited", "click", "confirm", "urgent"]
        features.append(1 if any(k in url.lower() for k in keywords) else 0)  # has_suspicious_keywords
        
        # Advanced features
        features.append(len(re.findall(r'\d', url)))  # digit_count
        features.append(len(re.findall(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>?]', url)))  # special_char_count
        
        # URL parsing features
        try:
            parsed = urlparse(url)
            subdomain_count = parsed.netloc.count('.') - 1 if parsed.netloc.count('.') > 0 else 0
            features.append(subdomain_count)  # subdomain_count
            
            # Check if domain contains IP address
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            features.append(1 if re.search(ip_pattern, parsed.netloc) else 0)  # has_ip
            
            # Suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.biz', '.info', '.cc']
            features.append(1 if any(tld in parsed.netloc for tld in suspicious_tlds) else 0)  # suspicious_tld
            
            features.append(len(parsed.path))  # path_length
            features.append(len(parsed.query) if parsed.query else 0)  # query_length
            
        except Exception:
            # If URL parsing fails, add default values
            features.extend([0, 0, 0, 0, 0])
        
        return features
    
    def load_and_preprocess_data(self, csv_path):
        """Load and preprocess the dataset"""
        print("📊 Loading dataset...")
        data = pd.read_csv(csv_path)
        print(f"✅ Loaded {len(data)} URLs")
        print(f"   - Legitimate URLs: {len(data[data['label'] == 0])}")
        print(f"   - Phishing URLs: {len(data[data['label'] == 1])}")
        
        # Extract features
        print("🔍 Extracting features...")
        X = np.array([self.extract_advanced_features(url) for url in data['url']])
        y = data['label'].values
        
        return X, y, data
    
    def train_model(self, X, y):
        """Train the phishing detection model"""
        print("🏋️ Training model...")
        
        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train model
        self.model = RandomForestClassifier(
            n_estimators=200, 
            random_state=42, 
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2
        )
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"✅ Model trained with accuracy: {accuracy:.3f}")
        print("\n📋 Classification Report:")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
        
        return X_test_scaled, y_test, y_pred
    
    def plot_feature_importance(self):
        """Plot feature importance"""
        if self.model is None:
            print("❌ Model not trained yet!")
            return
        
        importances = self.model.feature_importances_
        indices = np.argsort(importances)[::-1]
        
        plt.figure(figsize=(12, 8))
        plt.title("Feature Importance in Phishing Detection")
        plt.bar(range(len(importances)), importances[indices])
        plt.xticks(range(len(importances)), [self.feature_names[i] for i in indices], rotation=45)
        plt.tight_layout()
        plt.show()
        
        print("🎯 Top 5 Most Important Features:")
        for i in range(5):
            feat_idx = indices[i]
            print(f"   {i+1}. {self.feature_names[feat_idx]}: {importances[feat_idx]:.3f}")
    
    def plot_confusion_matrix(self, y_test, y_pred):
        """Plot confusion matrix"""
        cm = confusion_matrix(y_test, y_pred)
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                    xticklabels=['Legitimate', 'Phishing'],
                    yticklabels=['Legitimate', 'Phishing'])
        plt.title('Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.show()
    
    def predict_url(self, url):
        """Predict if a single URL is phishing or legitimate"""
        if self.model is None:
            print("❌ Model not trained yet!")
            return None
        
        features = np.array(self.extract_advanced_features(url)).reshape(1, -1)
        features_scaled = self.scaler.transform(features)
        
        prediction = self.model.predict(features_scaled)[0]
        probability = self.model.predict_proba(features_scaled)[0]
        
        return {
            'url': url,
            'prediction': 'Phishing' if prediction == 1 else 'Legitimate',
            'confidence': max(probability),
            'phishing_probability': probability[1]
        }
    
    def analyze_urls(self, urls):
        """Analyze multiple URLs"""
        print("🔍 Analyzing URLs...")
        results = []
        
        for url in urls:
            result = self.predict_url(url)
            results.append(result)
            
            status_emoji = "🚨" if result['prediction'] == 'Phishing' else "✅"
            print(f"{status_emoji} {result['url']}")
            print(f"   Prediction: {result['prediction']} (Confidence: {result['confidence']:.3f})")
            print(f"   Phishing Probability: {result['phishing_probability']:.3f}")
            print()
        
        return results

def main():
    print("🔒 Advanced Phishing Detection System")
    print("=" * 50)
    
    # Initialize detector
    detector = PhishingDetector()
    
    # Load and preprocess data
    X, y, data = detector.load_and_preprocess_data("phishing_dataset.csv")
    
    # Train model
    X_test, y_test, y_pred = detector.train_model(X, y)
    
    # Plot results
    print("\n📊 Generating visualizations...")
    detector.plot_feature_importance()
    detector.plot_confusion_matrix(y_test, y_pred)
    
    # Test on new URLs
    print("\n🧪 Testing on sample URLs:")
    print("=" * 30)
    
    test_urls = [
        "http://secure-login-update.com/bankofamerica",
        "https://www.google.com",
        "http://192.168.0.1/login",
        "https://secure.bank.com/account/verify",
        "http://paypal-verify.net/account/urgent",
        "https://github.com/user/repo",
        "http://amazon.security.fake.com/update",
        "https://www.microsoft.com",
        "http://facebook.login.phish.tk",
        "https://www.stackoverflow.com"
    ]
    
    results = detector.analyze_urls(test_urls)
    
    # Summary
    phishing_count = sum(1 for r in results if r['prediction'] == 'Phishing')
    print(f"📈 Summary: {phishing_count}/{len(results)} URLs detected as phishing")

if __name__ == "__main__":
    main()
