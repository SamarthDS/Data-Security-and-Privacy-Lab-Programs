import pandas as pd
import numpy as np
import re
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# ---------- Feature Extraction ----------
def extract_features(url):
    features = []
    # Length of URL
    features.append(len(url))
    # Presence of @
    features.append(1 if "@" in url else 0)
    # Presence of //
    features.append(1 if "//" in url[url.find("//")+2:] else 0)
    # HTTPS or not
    features.append(1 if url.startswith("https") else 0)
    # Count of dots
    features.append(url.count("."))
    # Suspicious keywords
    keywords = ["secure", "account", "update", "bank", "login", "verify"]
    features.append(1 if any(k in url.lower() for k in keywords) else 0)
    return features

# ---------- Load Dataset ----------
# Example dataset structure: url,label (1=phishing, 0=legit)
# You can use public dataset like: https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection
data = pd.read_csv("phishing_dataset.csv")  

# Extract features for all URLs
X = np.array([extract_features(url) for url in data['url']])
y = data['label'].values

# ---------- Train-Test Split ----------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# ---------- Model Training ----------
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# ---------- Evaluation ----------
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# ---------- Test on new URLs ----------
test_urls = [
    "http://secure-login-update.com/bankofamerica",
    "https://www.google.com",
    "http://192.168.0.1/login",
    "https://secure.bank.com/account/verify"
]

for url in test_urls:
    features = np.array(extract_features(url)).reshape(1, -1)
    prediction = model.predict(features)[0]
    print(f"{url} -> {'Phishing' if prediction==1 else 'Legit'}")
