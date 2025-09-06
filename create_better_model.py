import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.metrics import classification_report, confusion_matrix
import joblib
from urllib.parse import urlparse
import re
import requests
from bs4 import BeautifulSoup
import time

def extract_robust_features(url):
    """Extract robust features that work well for phishing detection"""
    features = {}
    
    try:
        # Basic URL features
        features['url_length'] = len(url)
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
        domain = parsed.netloc.lower()
        path = parsed.path
        query = parsed.query
        
        # Domain analysis
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        features['query_length'] = len(query)
        
        # Character analysis
        features['dot_count'] = url.count('.')
        features['hyphen_count'] = url.count('-')
        features['underscore_count'] = url.count('_')
        features['slash_count'] = url.count('/')
        features['question_count'] = url.count('?')
        features['equal_count'] = url.count('=')
        features['at_count'] = url.count('@')
        features['and_count'] = url.count('&')
        
        # Protocol and security
        features['is_https'] = 1 if url.startswith('https://') else 0
        features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0
        
        # Suspicious patterns
        suspicious_words = ['secure', 'account', 'update', 'confirm', 'verify', 'login', 'signin', 'bank', 'paypal', 'amazon']
        features['has_suspicious_words'] = 1 if any(word in url.lower() for word in suspicious_words) else 0
        
        # Subdomain analysis
        subdomains = domain.split('.')
        if len(subdomains) > 2:
            non_www_subdomains = [s for s in subdomains[:-2] if s.lower() != 'www']
            features['subdomain_count'] = len(non_www_subdomains)
        else:
            features['subdomain_count'] = 0
        
        # Domain entropy (randomness measure)
        def calculate_entropy(s):
            if not s: return 0
            prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
            return -sum(p * np.log2(p) for p in prob if p > 0)
        
        features['domain_entropy'] = calculate_entropy(domain)
        
        # TLD analysis
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
        features['suspicious_tld'] = 1 if any(tld in url.lower() for tld in suspicious_tlds) else 0
        
        # URL shortening services
        shortening_services = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'short.link']
        features['is_shortened'] = 1 if any(service in url.lower() for service in shortening_services) else 0
        
        # Additional robust features
        features['digit_ratio'] = sum(c.isdigit() for c in domain) / len(domain) if domain else 0
        features['vowel_ratio'] = sum(c.lower() in 'aeiou' for c in domain) / len(domain) if domain else 0
        features['consecutive_chars'] = max(len(match.group()) for match in re.finditer(r'(.)\1+', domain)) if domain else 0
        
        # Content features (simplified for robustness)
        features['page_length'] = 0
        features['word_count'] = 0
        features['form_count'] = 0
        features['has_password_field'] = 0
        features['total_links'] = 0
        features['external_links'] = 0
        features['urgency_score'] = 0
        features['fear_score'] = 0
        features['brand_mentions'] = 0
        features['credibility_score'] = 0
        
    except Exception as e:
        print(f"Error extracting features for {url}: {e}")
        # Return default features
        default_features = {
            'url_length': 0, 'domain_length': 0, 'path_length': 0, 'query_length': 0,
            'dot_count': 0, 'hyphen_count': 0, 'underscore_count': 0, 'slash_count': 0,
            'question_count': 0, 'equal_count': 0, 'at_count': 0, 'and_count': 0,
            'is_https': 0, 'has_ip': 0, 'has_suspicious_words': 0, 'subdomain_count': 0,
            'domain_entropy': 0, 'suspicious_tld': 0, 'is_shortened': 0,
            'digit_ratio': 0, 'vowel_ratio': 0, 'consecutive_chars': 0,
            'page_length': 0, 'word_count': 0, 'form_count': 0, 'has_password_field': 0,
            'total_links': 0, 'external_links': 0, 'urgency_score': 0, 'fear_score': 0,
            'brand_mentions': 0, 'credibility_score': 0
        }
        return default_features
        
    return features

def create_synthetic_dataset():
    """Create a synthetic dataset with proper legitimate and phishing examples"""
    print("Creating synthetic dataset...")
    
    # Legitimate URL patterns
    legitimate_patterns = [
        "https://www.google.com",
        "https://github.com",
        "https://stackoverflow.com",
        "https://www.amazon.com",
        "https://www.microsoft.com",
        "https://www.apple.com",
        "https://www.facebook.com",
        "https://www.twitter.com",
        "https://www.linkedin.com",
        "https://www.youtube.com",
        "https://www.netflix.com",
        "https://www.spotify.com",
        "https://www.dropbox.com",
        "https://www.adobe.com",
        "https://www.salesforce.com",
        "https://www.walmart.com",
        "https://www.flipkart.com",
        "https://www.ebay.com",
        "https://www.target.com",
        "https://www.bestbuy.com"
    ]
    
    # Phishing URL patterns
    phishing_patterns = [
        "http://paypal-security-update.suspicious-domain.tk/login.php",
        "http://amazon-account-verify.ml/secure",
        "http://apple-id-confirm.ga/update",
        "http://microsoft-security-alert.tk/verify",
        "http://google-account-suspended.cf/login",
        "http://facebook-security-check.ml/confirm",
        "http://bank-account-update.tk/secure",
        "http://paypal-limited-time-offer.ga/click",
        "http://amazon-prize-winner.ml/claim",
        "http://apple-gift-card.tk/redeem",
        "http://microsoft-tech-support.cf/help",
        "http://google-drive-storage.ml/upgrade",
        "http://facebook-message-alert.tk/view",
        "http://bank-fraud-alert.ga/verify",
        "http://paypal-payment-failed.ml/fix"
    ]
    
    # Generate variations
    legitimate_urls = []
    phishing_urls = []
    
    # Add legitimate variations
    for base_url in legitimate_patterns:
        legitimate_urls.append(base_url)
        legitimate_urls.append(base_url + "/")
        legitimate_urls.append(base_url + "/search")
        legitimate_urls.append(base_url + "/about")
        legitimate_urls.append(base_url + "/contact")
    
    # Add phishing variations
    for base_url in phishing_patterns:
        phishing_urls.append(base_url)
        phishing_urls.append(base_url + "?id=123")
        phishing_urls.append(base_url + "&ref=email")
        phishing_urls.append(base_url.replace("http://", "https://"))
    
    # Extract features
    legitimate_features = []
    phishing_features = []
    
    print("Extracting features for legitimate URLs...")
    for url in legitimate_urls[:100]:  # Limit for demo
        features = extract_robust_features(url)
        features['label'] = 0
        legitimate_features.append(features)
    
    print("Extracting features for phishing URLs...")
    for url in phishing_urls[:100]:  # Limit for demo
        features = extract_robust_features(url)
        features['label'] = 1
        phishing_features.append(features)
    
    # Combine datasets
    all_features = legitimate_features + phishing_features
    df = pd.DataFrame(all_features)
    
    print(f"Created dataset with {len(df)} samples")
    print(f"Legitimate: {sum(df['label'] == 0)}")
    print(f"Phishing: {sum(df['label'] == 1)}")
    
    return df

def train_better_model():
    """Train a better model with proper data"""
    print("Creating synthetic dataset...")
    df = create_synthetic_dataset()
    
    # Prepare features
    feature_columns = [col for col in df.columns if col != 'label']
    X = df[feature_columns]
    y = df['label']
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Feature selection
    selector = SelectKBest(f_classif, k=15)
    X_train_selected = selector.fit_transform(X_train_scaled, y_train)
    X_test_selected = selector.transform(X_test_scaled)
    
    # Train model
    print("Training Random Forest model...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
    model.fit(X_train_selected, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test_selected)
    print("\nModel Performance:")
    print(classification_report(y_test, y_pred))
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Save model and preprocessing objects
    joblib.dump(model, 'better_phishing_model.pkl')
    joblib.dump(scaler, 'better_feature_scaler.pkl')
    joblib.dump(selector, 'better_feature_selector.pkl')
    
    # Save feature names
    df[feature_columns].to_csv('better_phishing_features.csv', index=False)
    
    print("\nModel saved as 'better_phishing_model.pkl'")
    print("Preprocessing objects saved")
    
    return model, scaler, selector, feature_columns

if __name__ == "__main__":
    train_better_model()
