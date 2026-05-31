import joblib
import sys
import pandas as pd
from feature_extractor import URLFeatureExtractor
import warnings
warnings.filterwarnings("ignore")
def analyze(url):
    print(f"Analyzing URL: {url}\n")
    
    # Load model
    try:
        model_data = joblib.load('best_model.pkl')
        model = model_data['model']
        columns = model_data['feature_columns']
    except FileNotFoundError:
        print("Error: 'best_model.pkl' not found. Please run train_model.py first.")
        return
        
    # Extract features
    print("Extracting features... (This might take a few seconds)")
    try:
        extractor = URLFeatureExtractor(top_domains_file=r"top_10000_domains.csv")
    except TypeError:
        extractor = URLFeatureExtractor()
        
    features = extractor.extract_features(url)
    
    if len(features) != len(columns):
        print(f"Error: Feature dimension mismatch. Model expects {len(columns)} but got {len(features)}.")
        return
        
    feature_df = pd.DataFrame([features], columns=columns)
    
    # Analyze with predict_proba instead of predict to handle sensitivity
    probabilities = model.predict_proba(feature_df)[0]
    classes = list(model.classes_)
    
    # Get the strict confidence score for Phishing (-1)
    if -1 in classes:
        phish_idx = classes.index(-1)
        phish_prob = probabilities[phish_idx]
    else:
        phish_prob = 0.0
        
    PHISHING_THRESHOLD = 0.85 
    
    if phish_prob >= PHISHING_THRESHOLD:
        result = "Phishing "
    else:
        result = "Legitimate "
        
    print("="*50)
    print(f"PREDICTION (Risk Score: {phish_prob*100:.1f}%):")
    print(f"The URL '{url}' is classified as {result}")
    print("="*50)
if __name__ == "__main__":
    if len(sys.argv) > 1:
        analyze(sys.argv[1])
    else:
        test_url = input("Enter a URL to analyze: ").strip()
        if test_url:
            analyze(test_url)
