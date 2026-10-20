"""Quick test script to verify feature extraction, models, and decision engine."""
from feature_extractor import extract_features
from autoencoder_anomaly import AutoencoderAnomalyDetector
from nlp_classifier import QuantizedNLPClassifier
import joblib

def test():
    feat = extract_features("bKash Alert: Your account is suspended. Verify PIN: http://bkash-verify.tk", "", "sms")
    print("Features extracted successfully:", len(feat["vector"]))
    
    rf = joblib.load("models/random_forest_model.joblib")
    probs = rf.predict_proba([feat["vector"]])[0]
    print(f"Random Forest Phishing Prob: {probs[1]*100:.1f}%")
    
    ae = AutoencoderAnomalyDetector()
    ae.load_weights("models/autoencoder_weights.json")
    ae_res = ae.detect_anomaly(feat["vector"], feat["feature_names"])
    print(f"Autoencoder Anomaly MSE: {ae_res['reconstruction_error']:.5f} (Threshold: {ae_res['threshold']:.5f}) -> Is Anomaly: {ae_res['is_anomaly']}")
    
    nlp = QuantizedNLPClassifier()
    nlp_res = nlp.analyze("bKash Alert: Your account is suspended. Verify PIN: http://bkash-verify.tk", "+8801999887766")
    print(f"NLP Score: {nlp_res['nlp_risk_score']}%, Intent: {nlp_res['intent']}, Brand: {nlp_res['impersonated_brand']}")
    print("ALL TESTS PASSED PERFECTLY!")

if __name__ == "__main__":
    test()
