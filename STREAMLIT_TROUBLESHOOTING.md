# 🚨 Streamlit Cloud Deployment Troubleshooting

## Common Deployment Issues & Solutions

### 1. **"Module not found" errors**
**Problem**: Missing dependencies
**Solution**: 
- Use `requirements_minimal.txt` instead of `requirements.txt`
- Ensure all imports are in the requirements file

### 2. **"File not found" errors**
**Problem**: Model files not accessible
**Solution**:
- All model files are included in the repository
- Use `app_simple.py` which has better error handling

### 3. **"Memory limit exceeded"**
**Problem**: App uses too much memory
**Solution**:
- Use the simplified version (`app_simple.py`)
- Model files are optimized for size

### 4. **"App crashes on startup"**
**Problem**: Import or initialization errors
**Solution**:
- Check Streamlit Cloud logs
- Use `app_simple.py` with better error handling

### 5. **"Timeout errors"**
**Problem**: App takes too long to load
**Solution**:
- Use `@st.cache_resource` decorator (already implemented)
- Simplified feature extraction

## Deployment Steps (Try Both Versions)

### Option 1: Use Simplified Version
1. Go to https://share.streamlit.io
2. Click "New app"
3. Repository: `Vipulgupta23/url-spam`
4. Branch: `main`
5. **Main file path**: `app_simple.py` ⬅️ **Use this instead of app.py**
6. Deploy!

### Option 2: Use Minimal Requirements
1. Same steps as above
2. **Main file path**: `app.py`
3. **Requirements file**: `requirements_minimal.txt` ⬅️ **Use this instead of requirements.txt**

## Testing Locally First

Before deploying, test locally:
```bash
streamlit run app_simple.py
```

## Streamlit Cloud Logs

If deployment fails:
1. Go to your app dashboard
2. Click "Logs" tab
3. Look for error messages
4. Share the error with me for specific help

## File Structure for Deployment

```
url-spam/
├── app.py                          # Full version
├── app_simple.py                   # Simplified version ⭐
├── requirements.txt                # Full requirements
├── requirements_minimal.txt        # Minimal requirements ⭐
├── .streamlit/config.toml          # Streamlit config
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

## Success Indicators

✅ App loads without errors
✅ Model loads successfully (green success message)
✅ URL analysis works
✅ Both legitimate and phishing URLs are tested

## If Still Not Working

1. **Try the simplified version first**: `app_simple.py`
2. **Use minimal requirements**: `requirements_minimal.txt`
3. **Check the logs** in Streamlit Cloud dashboard
4. **Share the specific error message** you're seeing

## Alternative Deployment Options

If Streamlit Cloud doesn't work:
1. **Heroku**: Free tier available
2. **Railway**: Easy deployment
3. **Render**: Simple deployment
4. **Local hosting**: Run on your own server
