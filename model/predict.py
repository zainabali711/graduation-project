import joblib
import pandas as pd
from features import extract_features

#
pipline = joblib.load("saved/hybrid_model.pkl")
def predict_url(url):
    #make sure if https is there
    if not url.startswith("http://", "https://"):
        url = "https://" + url
    
    #extract lexical features from url
    features = extract_features(url)
    X = pd.DataFrame([features])

    #Classification prediction
    prediction = pipline.predict(X)[0]

    #calculate per of trust
    propability = pipline.predict_proba(X)[0]
    benign_prob = round(propability[0] * 100, 2)
    malicious_prob = round(propability[1] * 100, 2)
    confidence = round(max(propability) * 100, 2)

    #set risk level
    if malicious_prob >= 75:
        risk_level = "high"
    elif malicious_prob >= 50:
        risk_level = "medium"
    elif malicious_prob >= 25:
        risk_level = "low"
    else:
        risk_level = "safe"
    
    #extract importants features (explainable AI)
    rf_model = pipline.named_steps["model"].estimators_[0]
    features_names = list(features.keys())
    importances = rf_model.feature_importances_

    top_features = sorted(
        zip(features_names, importances, X.values[0]),
        key=lambda x: x[1],
        reverse=True
    )[:6]

    explanation = []
    for name, imp, val in top_features:
        explanation.append({
            "features": name, 
            "importance": round(imp * 100, 1),
            "value": round(float(val), 3)
        })
    
    #taking back all result to dictionary
    return {
        "url": url,
        "label": "malicious" if prediction == 1 else "benign",
        "is_malicious": bool(prediction == 1),
        "confidence": confidence,
        "malicious_probability": malicious_prob,
        "benign_probability": benign_prob,
        "risk-level": risk_level,
        "features": features,
        "explanation": explanation
    }

  


