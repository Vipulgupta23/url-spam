# 🚀 Streamlit Cloud Deployment Guide

## Prerequisites
- GitHub repository: https://github.com/Vipulgupta23/url-spam.git
- Streamlit Cloud account (free at https://share.streamlit.io)

## Deployment Steps

### 1. Prepare Repository
✅ All files are already committed and pushed to GitHub
✅ Requirements.txt is properly configured
✅ Streamlit config is set up

### 2. Deploy on Streamlit Cloud

1. **Go to Streamlit Cloud**: https://share.streamlit.io
2. **Sign in** with your GitHub account
3. **Click "New app"**
4. **Fill in the details**:
   - **Repository**: `Vipulgupta23/url-spam`
   - **Branch**: `main`
   - **Main file path**: `app.py`
   - **App URL**: Choose a custom URL (e.g., `url-phishing-detector`)

5. **Click "Deploy!"**

### 3. Troubleshooting Common Issues

#### Issue: "Module not found" errors
**Solution**: Ensure all dependencies are in `requirements.txt`

#### Issue: "File not found" errors
**Solution**: All model files are included in the repository

#### Issue: "Memory limit exceeded"
**Solution**: The app uses efficient models and should fit within limits

#### Issue: "App crashes on startup"
**Solution**: Check the logs in Streamlit Cloud dashboard

### 4. Environment Variables (if needed)
If you need to set environment variables:
1. Go to your app dashboard
2. Click "Settings"
3. Add environment variables in "Secrets"

### 5. Monitoring
- Check app logs in Streamlit Cloud dashboard
- Monitor performance and usage
- Update dependencies as needed

## File Structure for Deployment
```
url-spam/
├── app.py                          # Main application
├── requirements.txt                 # Dependencies
├── .streamlit/config.toml          # Streamlit config
├── .gitignore                      # Git ignore rules
├── README.md                       # Documentation
├── DEPLOYMENT.md                   # This file
├── better_phishing_model.pkl       # Primary model
├── better_feature_scaler.pkl       # Feature scaler
├── better_feature_selector.pkl     # Feature selector
├── better_phishing_features.csv    # Feature definitions
├── best_phishing_model.pkl         # Fallback model
├── feature_scaler.pkl              # Fallback scaler
├── feature_selector.pkl            # Fallback selector
├── phishing_features.csv           # Original training data
└── tfidf_vectorizer_*.joblib       # TF-IDF vectorizers
```

## Performance Optimization
- Model files are optimized for size
- Efficient feature extraction
- Caching enabled for better performance
- Minimal memory footprint

## Security Notes
- No sensitive data in the repository
- All models are pre-trained and safe
- HTTPS verification disabled for web scraping (intentional)

## Support
If deployment fails:
1. Check Streamlit Cloud logs
2. Verify all files are in the repository
3. Ensure requirements.txt is correct
4. Check for any import errors

## Success Indicators
✅ App loads without errors
✅ Model loads successfully
✅ URL analysis works
✅ Both legitimate and phishing URLs are tested
