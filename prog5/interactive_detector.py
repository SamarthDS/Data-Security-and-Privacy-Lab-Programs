#!/usr/bin/env python3
"""
Interactive Phishing URL Detector
Test individual URLs for phishing detection
"""

import sys
sys.path.append('.')

from enhanced_phishing_detector import PhishingDetector
import pandas as pd

def interactive_detection():
    print("🔒 Interactive Phishing URL Detector")
    print("=" * 50)
    
    # Load and train model
    print("🔄 Loading and training model...")
    detector = PhishingDetector()
    
    try:
        X, y, data = detector.load_and_preprocess_data("phishing_dataset.csv")
        detector.train_model(X, y)
        print("✅ Model ready!\n")
    except FileNotFoundError:
        print("❌ Dataset file 'phishing_dataset.csv' not found!")
        print("Please make sure the dataset file exists in the current directory.")
        return
    
    print("Enter URLs to analyze (type 'quit' to exit):")
    print("Examples:")
    print("  - https://www.google.com")
    print("  - http://secure-bank-login.suspicious.tk")
    print()
    
    while True:
        try:
            url = input("🌐 Enter URL: ").strip()
            
            if url.lower() in ['quit', 'exit', 'q']:
                print("👋 Goodbye!")
                break
            
            if not url:
                print("⚠️  Please enter a valid URL")
                continue
            
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            # Analyze URL
            result = detector.predict_url(url)
            
            if result:
                status_emoji = "🚨" if result['prediction'] == 'Phishing' else "✅"
                risk_level = "HIGH" if result['phishing_probability'] > 0.8 else "MEDIUM" if result['phishing_probability'] > 0.5 else "LOW"
                
                print(f"\n{status_emoji} Analysis Result:")
                print(f"   URL: {result['url']}")
                print(f"   Prediction: {result['prediction']}")
                print(f"   Confidence: {result['confidence']:.1%}")
                print(f"   Phishing Probability: {result['phishing_probability']:.1%}")
                print(f"   Risk Level: {risk_level}")
                
                # Additional warnings
                if result['prediction'] == 'Phishing':
                    print("\n⚠️  WARNING: This URL appears to be malicious!")
                    print("   - Do not enter personal information")
                    print("   - Do not download files")
                    print("   - Consider reporting to security authorities")
                else:
                    print("\n✅ This URL appears to be legitimate")
                    if result['phishing_probability'] > 0.3:
                        print(f"   - However, phishing probability is {result['phishing_probability']:.1%}")
                        print("   - Please exercise caution")
                
                print()
            
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error analyzing URL: {str(e)}")
            print("Please try again with a different URL.\n")

if __name__ == "__main__":
    interactive_detection()
