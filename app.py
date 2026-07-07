from flask import Flask, render_template, request
from model.predict import predict_url
import json
import os

# creat flask app 
app = Flask(__name__)

# home page
@app.route("/")
def index():
    return render_template("index.html")

# predict page
@app.route("/predict", methods=["POST"])
def predict():
    url = request.form.get("url", "").strip()

    if not url:
        return render_template(
            "index.html",
            error= "please enter a valid url"
        )
    result = predict_url(url)
    return render_template("result.html", result=result)

# status page
@app.route("/status")
def status():
    metrics_path = os.path.join("model", "saved", "metrics.json")

    if os.path.exists(metrics_path):
        with open(metrics_path) as f:
            metrics = json.load(f)
    else:
        metrics = None

    return render_template("stats.html", metrics=metrics)

# run app
if __name__ == "__main__":
    app.run(debug=True, port=5000)