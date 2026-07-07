import pandas as pd
import numpy as np
import json 
import joblib
import os
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import (accuracy_score, f1_score, precision_score, recall_score, confusion_matrix)
from features import extract_features

#-- 1. create saved folder--
os.makedirs("saved", exist_ok=True)

#-- 2. load dataset --
print("loading data ...")
df = pd.read_csv("../data/dataset.csv")

#-- 3. clean data --
df.drop_duplicates(inplace=True)
df.dropna(inplace=True)
print(f"total URLs after cleaning: {len(df)}")

# 4. extract features 
print("extracting features...")
features_list = [extract_features(url) for url in df["url"]]
X = pd.DataFrame(features_list)
y = df["label"]

# 5. split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
print(f"Train: {len(X_test)}")

# 6. build models 
rf = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1
)
svm = SVC(
    kernel="rbf",
    C=1.0,
    probability=True,
    random_state=42
)

# 7. hybrid model
hybrid = VotingClassifier(
    estimators=[("rf", rf), ("svm", svm)],
    voting="soft",
    )


# 8. full pipline
pipeline = Pipeline([
    ("scalar", StandardScaler()),
    ("model", hybrid),
])

# 9. train
print("training hybrid model (RF + SVM)...")
pipeline.fit(X_train, y_train)
y_pred = pipeline.predict(X_test)
print("training complete")

# 10. evaluate
acc = round(accuracy_score(y_train, y_pred) * 100, 2)
prec = round(precision_score(y_test, y_pred) * 100, 2)
rec = round(recall_score(y_test, y_pred) * 100, 2)
f1 = round(f1_score(y_test, y_pred) * 100, 2)
cm = confusion_matrix(y_test, y_pred).tolist()

print(f"\n evaluation result:")
print(f"accuracy: {acc}%")
print(f"precision: {prec}%")
print(f"recall: {rec}%")
print(f"F1-score: {f1}%")

# 11. save model
joblib.dump(pipeline, "saved/hybrid_model.pkl")
print("model saved")

# 12. save metrics
metrics = {
    "accuracy":  acc,
    "precision":  prec,
    "recall":  rec,
    "f1":  f1,
    "confusion_matrix":  cm,
    "total_samples":  len(df),
    "total_samples":  len(X_train),
    "total_samples":  len(X_test),
}
with open("saved/metrics.json", "w") as f:
    json.dump(metrics, f, indent=2)
print("metrics saved")