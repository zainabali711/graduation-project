# URL⚡SHIELD — Malicious URL & DNS Detection System

A production-ready web-based system that classifies URLs and DNS domains as **Malicious** or **Benign** using a Hybrid ML Model (Random Forest + SVM with Soft Voting).

## Features

- 20 URL/DNS feature extraction (entropy, TLD analysis, IP detection, etc.)
- Hybrid ML model with Soft Voting ensemble
- Explainable AI with feature importance
- Arabic RTL web interface with dark theme
- REST API endpoint for programmatic access
- Model performance statistics page

## Tech Stack

| Layer | Technology |
|-------|------------|
| Language | Python 3.10+ |
| Backend | Flask |
| ML | Scikit-Learn |
| Data | Pandas, NumPy |
| Frontend | HTML5, CSS3, Bootstrap 5 |
| Model Storage | joblib |

## Project Structure

```
url-shield/
├── app.py                  # Flask main application
├── requirements.txt        # Dependencies
├── model/
│   ├── train.py            # Training script
│   ├── predict.py          # Prediction + explainability
│   ├── features.py         # Feature extraction
│   └── saved/
│       ├── hybrid_model.pkl
│       ├── scaler.pkl
│       └── metrics.json
├── data/
│   └── dataset.csv         # Training dataset
├── static/
│   ├── css/style.css
│   └── js/main.js
└── templates/
    ├── index.html
    ├── result.html
    └── stats.html
```

## Quick Start

### 1. Install Dependencies

```bash
cd url-shield
pip install -r requirements.txt
```

### 2. Generate Dataset (if needed)

```bash
python data/generate_dataset.py
```

### 3. Train the Model

```bash
python model/train.py
```

This will:
- Load and preprocess `data/dataset.csv`
- Extract features from all URLs
- Train the hybrid VotingClassifier pipeline
- Save the model to `model/saved/hybrid_model.pkl`
- Save metrics to `model/saved/metrics.json`

### 4. Run the Application

```bash
python app.py
```

Open your browser at: **http://127.0.0.1:5000**

## API Usage

```bash
curl -X POST http://127.0.0.1:5000/api/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

## Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Home page with URL input |
| `/predict` | POST | Form-based URL scan |
| `/api/predict` | POST | JSON API prediction |
| `/stats` | GET | Model performance metrics |
| `/about` | GET | About page |

## License

MIT
