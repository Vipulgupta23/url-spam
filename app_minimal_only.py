import streamlit as st
import pandas as pd
import numpy as np
import joblib
import re
from urllib.parse import urlparse
import time
import warnings
warnings.filterwarnings('ignore')

# Page config
st.set_page_config(
    page_title="🛡️ URL Phishing Detector",
    page_icon="🛡️",
    layout="wide"
)

class PhishingDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_selector = None
        self.feature_names = None
        
    def extract_url_features(self, url):
        """Extract features from URL"""
        features = {}
        
        try:
            features['url_length'] = len(url)
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
            domain = parsed.netloc
            path = parsed.path
            query = parsed.query
            
            # Set domain_length to 0 to match training data
            features['domain_length'] = 0
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
            
            # Count subdomains, but don't count 'www' as suspicious
            subdomains = domain.split('.')
            if len(subdomains) > 2:
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
    
    def extract_content_features(self, url):
        """Extract basic content features without web scraping"""
        features = {
            'page_length': 0, 'word_count': 0, 'form_count': 0, 'has_password_field': 0,
            'total_links': 0, 'external_links': 0, 'urgency_score': 0, 'fear_score': 0,
            'brand_mentions': 0, 'credibility_score': 0
        }
        return features
    
    def extract_all_features(self, url):
        """Extract all features"""
        url_features = self.extract_url_features(url)
        content_features = self.extract_content_features(url)
        return {**url_features, **content_features}
    
    def load_model(self):
        """Load pre-trained model and preprocessing objects"""
        try:
            # Try to load the better model first
            try:
                self.model = joblib.load('better_phishing_model.pkl')
                self.scaler = joblib.load('better_feature_scaler.pkl')
                self.feature_selector = joblib.load('better_feature_selector.pkl')
                df = pd.read_csv('better_phishing_features.csv')
                self.feature_names = [col for col in df.columns if col != 'label']
                st.success("✅ Loaded better model successfully!")
            except FileNotFoundError:
                # Fallback to original model
                self.model = joblib.load('best_phishing_model.pkl')
                self.scaler = joblib.load('feature_scaler.pkl')
                self.feature_selector = joblib.load('feature_selector.pkl')
                df = pd.read_csv('phishing_features.csv')
                self.feature_names = [col for col in df.columns if col != 'label']
                st.info("ℹ️ Loaded original model (better model not found)")
            
            return True
        except Exception as e:
            st.error(f"❌ Error loading model: {e}")
            return False
    
    def predict_url(self, url):
        """Predict if URL is phishing"""
        try:
            start_time = time.time()
            features = self.extract_all_features(url)
            feature_df = pd.DataFrame([features])
            
            # Ensure all expected features are present
            for feature in self.feature_names:
                if feature not in feature_df.columns:
                    feature_df[feature] = 0
            
            # Select features in the same order as training
            feature_df = feature_df[self.feature_names]
            
            # Apply scaling first
            if self.scaler is not None:
                feature_df = self.scaler.transform(feature_df)
            
            # Apply feature selection after scaling
            if self.feature_selector is not None:
                feature_df = self.feature_selector.transform(feature_df)
            
            # Make prediction
            prediction = self.model.predict(feature_df)[0]
            probability = self.model.predict_proba(feature_df)[0]
            
            processing_time = time.time() - start_time
            
            return {
                'url': url,
                'prediction': 'Phishing' if prediction == 1 else 'Legitimate',
                'confidence': float(max(probability)),
                'phishing_probability': float(probability[1]),
                'processing_time': processing_time,
                'features': features
            }
            
        except Exception as e:
            return {'url': url, 'prediction': 'Error', 'error': str(e)}

# Initialize app
@st.cache_resource
def load_detector():
    detector = PhishingDetector()
    detector.load_model()
    return detector

def main():
    st.title("🛡️ URL Phishing Detection System")
    st.markdown("**Real-time URL analysis with machine learning**")
    
    # Load detector
    detector = load_detector()
    
    if detector.model is None:
        st.error("⚠️ Model not loaded! Please ensure model files are in the app directory.")
        st.stop()
    
    # Sidebar
    st.sidebar.title("🔧 About")
    st.sidebar.info("""
    This system analyzes URLs in real-time to detect phishing attempts using machine learning.
    
    **Features:**
    - Real-time URL analysis
    - URL structure analysis
    - Machine learning prediction
    - Risk assessment
    """)
    
    # Main interface
    st.header("🔍 URL Analysis")
    
    url_input = st.text_input("🌐 Enter URL to analyze:", 
                             placeholder="https://example.com",
                             help="Enter the full URL including http:// or https://")
    
    col1, col2 = st.columns([1, 1])
    with col1:
        analyze_btn = st.button("🔍 Analyze URL", type="primary")
    with col2:
        sample_btn = st.button("🧪 Try Sample Phishing URL")
    
    if sample_btn:
        url_input = "http://paypal-security-update.suspicious-domain.tk/login.php"
        st.rerun()
    
    if analyze_btn and url_input:
        with st.spinner("🔍 Analyzing URL..."):
            result = detector.predict_url(url_input)
        
        if result['prediction'] != 'Error':
            # Main result
            col1, col2, col3 = st.columns(3)
            with col1:
                if result['prediction'] == 'Phishing':
                    st.error(f"🚨 **{result['prediction']}**")
                else:
                    st.success(f"✅ **{result['prediction']}**")
            with col2:
                st.metric("Confidence", f"{result['confidence']:.1%}")
            with col3:
                st.metric("Processing Time", f"{result['processing_time']:.2f}s")
            
            # Simple risk indicator
            risk_percentage = result['phishing_probability'] * 100
            if risk_percentage < 30:
                st.success(f"🟢 **Low Risk**: {risk_percentage:.1f}% phishing probability")
            elif risk_percentage < 70:
                st.warning(f"🟡 **Medium Risk**: {risk_percentage:.1f}% phishing probability")
            else:
                st.error(f"🔴 **High Risk**: {risk_percentage:.1f}% phishing probability")
            
            # Feature analysis
            st.subheader("🔍 Feature Analysis")
            features = result['features']
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("URL Length", features.get('url_length', 0))
                st.metric("HTTPS", "Yes" if features.get('is_https', 0) else "No")
            with col2:
                st.metric("Subdomains", features.get('subdomain_count', 0))
                st.metric("Suspicious Words", "Yes" if features.get('has_suspicious_words', 0) else "No")
            with col3:
                st.metric("Domain Entropy", f"{features.get('domain_entropy', 0):.2f}")
                st.metric("Suspicious TLD", "Yes" if features.get('suspicious_tld', 0) else "No")
            with col4:
                st.metric("Shortened URL", "Yes" if features.get('is_shortened', 0) else "No")
                st.metric("Has IP", "Yes" if features.get('has_ip', 0) else "No")
                
        else:
            st.error(f"❌ Analysis failed: {result.get('error', 'Unknown error')}")
    
    # Footer
    st.markdown("---")
    st.markdown("**🛡️ Stay safe online! This tool helps identify suspicious URLs but always verify through multiple sources.**")

if __name__ == "__main__":
    main()
