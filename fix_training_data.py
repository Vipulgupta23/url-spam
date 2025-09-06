import pandas as pd
import numpy as np
from urllib.parse import urlparse
import re
import requests
from bs4 import BeautifulSoup
import time
import warnings
warnings.filterwarnings('ignore')

def extract_url_features_fixed(url):
    """Extract features from URL with proper parsing"""
    features = {}
    
    try:
        features['url_length'] = len(url)
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
        
        # Fix domain_length - this was the main issue
        features['domain_length'] = len(domain) if domain else 0
        features['path_length'] = len(path)
        features['query_length'] = len(query)
        features['dot_count'] = url.count('.')
        features['hyphen_count'] = url.count('-')
        features['underscore_count'] = url.count('_')
        features['slash_count'] = url.count('/')
        features['question_count'] = url.count('?')
        features['equal_count'] = url.count('=')
        features['at_count'] = url.count('@')
        features['and_count'] = url.count('&')
        features['is_https'] = 1 if url.startswith('https://') else 0
        features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0
        
        suspicious_words = ['secure', 'account', 'update', 'confirm', 'verify', 'login', 'signin', 'bank']
        features['has_suspicious_words'] = 1 if any(word in url.lower() for word in suspicious_words) else 0
        
        # Fix subdomain counting
        subdomains = domain.split('.')
        if len(subdomains) > 2:
            # Remove 'www' from subdomain count as it's common and legitimate
            non_www_subdomains = [s for s in subdomains[:-2] if s.lower() != 'www']
            features['subdomain_count'] = len(non_www_subdomains)
        else:
            features['subdomain_count'] = 0
        
        def calculate_entropy(s):
            if not s: return 0
            prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
            return -sum(p * np.log2(p) for p in prob if p > 0)
        
        features['domain_entropy'] = calculate_entropy(domain)
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
        features['suspicious_tld'] = 1 if any(tld in url.lower() for tld in suspicious_tlds) else 0
        shortening_services = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly']
        features['is_shortened'] = 1 if any(service in url.lower() for service in shortening_services) else 0
        
    except Exception:
        feature_names = ['url_length', 'domain_length', 'path_length', 'query_length', 
                       'dot_count', 'hyphen_count', 'underscore_count', 'slash_count',
                       'question_count', 'equal_count', 'at_count', 'and_count',
                       'is_https', 'has_ip', 'has_suspicious_words', 'subdomain_count',
                       'domain_entropy', 'suspicious_tld', 'is_shortened']
        features = {name: 0 for name in feature_names}
        
    return features

def extract_content_features_fixed(url, timeout=3):
    """Extract features from webpage content"""
    features = {
        'page_length': 0, 'word_count': 0, 'form_count': 0, 'has_password_field': 0,
        'total_links': 0, 'external_links': 0, 'urgency_score': 0, 'fear_score': 0,
        'brand_mentions': 0, 'credibility_score': 0
    }
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=timeout, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        text_content = soup.get_text()
        features['page_length'] = len(text_content)
        features['word_count'] = len(text_content.split())
        features['form_count'] = len(soup.find_all('form'))
        features['has_password_field'] = 1 if soup.find_all('input', {'type': 'password'}) else 0
        
        links = soup.find_all('a', href=True)
        features['total_links'] = len(links)
        domain = urlparse(url).netloc
        features['external_links'] = sum(1 for link in links 
                                       if link['href'].startswith('http') and domain not in link['href'])
        
        text_lower = text_content.lower()
        urgency_words = ['urgent', 'immediate', 'act now', 'limited time', 'expires']
        features['urgency_score'] = sum(1 for word in urgency_words if word in text_lower)
        fear_words = ['suspended', 'blocked', 'cancelled', 'terminated', 'frozen']
        features['fear_score'] = sum(1 for word in fear_words if word in text_lower)
        brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook']
        features['brand_mentions'] = sum(1 for brand in brands if brand in text_lower)
        credible_words = ['https', 'secure', 'privacy', 'terms', 'policy']
        features['credibility_score'] = sum(1 for word in credible_words if word in text_lower)
        
    except Exception:
        pass
        
    return features

def fix_training_data():
    """Fix the corrupted training data"""
    print("Loading original training data...")
    df = pd.read_csv('phishing_features.csv')
    
    print(f"Original data shape: {df.shape}")
    print(f"HTTPS distribution:")
    print(f"  Legitimate: {sum(df[df['label'] == 0]['is_https'])}")
    print(f"  Phishing: {sum(df[df['label'] == 1]['is_https'])}")
    
    # Create new dataset with proper feature extraction
    print("\nRegenerating features with proper parsing...")
    new_features = []
    
    # Sample a subset for testing (you can increase this)
    sample_size = min(1000, len(df))
    sample_df = df.sample(n=sample_size, random_state=42)
    
    for idx, row in sample_df.iterrows():
        if idx % 100 == 0:
            print(f"Processing {idx}/{sample_size}")
        
        # Extract URL from the original data (you'll need to provide URLs)
        # For now, let's create synthetic URLs based on the features
        url_features = extract_url_features_fixed("https://example.com")  # Placeholder
        
        # Combine with content features
        content_features = extract_content_features_fixed("https://example.com")  # Placeholder
        
        all_features = {**url_features, **content_features}
        all_features['label'] = row['label']
        new_features.append(all_features)
        
        time.sleep(0.1)  # Rate limiting
    
    new_df = pd.DataFrame(new_features)
    new_df.to_csv('phishing_features_fixed.csv', index=False)
    
    print(f"\nFixed data shape: {new_df.shape}")
    print(f"HTTPS distribution in fixed data:")
    print(f"  Legitimate: {sum(new_df[new_df['label'] == 0]['is_https'])}")
    print(f"  Phishing: {sum(new_df[new_df['label'] == 1]['is_https'])}")
    
    return new_df

if __name__ == "__main__":
    fix_training_data()
