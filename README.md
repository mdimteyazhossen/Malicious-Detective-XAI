# 🔍 Malicious Detective XAI

**Explainable AI for Phishing & Malware URL Detection**

Malicious Detective XAI is a live, web-based multi-class URL classifier that distinguishes between **Benign**, **Phishing**, **Malware**, and **Defacement** URLs. Built with a **LightGBM** model trained on 30,000+ real-world URLs, this tool demonstrates the power of **Explainable AI (LIME)** for transparent threat analysis in cybersecurity.

🌐 **Live Demo:** [Malicious Detective XAI on Streamlit](https://malicious-detective-xai.streamlit.app/)

📓 **Kaggle Notebook:** [Model Training & Feature Engineering](https://www.kaggle.com/code/mdimteyazhossen/)

---

## 🎯 Features

- **Multi-class URL Classification:** Predicts whether a URL is **Benign**, **Phishing**, **Malware**, or **Defacement**.
- **Explainable AI (XAI):** Uses **LIME (Local Interpretable Model-agnostic Explanations)** to highlight which features (e.g., URL length, presence of '@', HTTPS) influenced the prediction.
- **Confidence Scores:** Displays probability percentages for all four classes.
- **Real-time Analysis:** Instant feedback with a clean, dark-themed UI.
- **Fully Responsive:** Custom CSS ensures a professional look on desktop, tablet, and mobile.

---

## 📸 Screenshots

| Malware Detection | Phishing Detection |
|:-----------------:|:------------------:|
| ![Malware Detection](<img width="927" height="653" alt="Screenshot 2026-04-17 144629" src="https://github.com/user-attachments/assets/5ad1f5e0-467a-4623-bc3c-73b5ef56ddce" />
) | ![Phishing Detection](<img width="901" height="660" alt="Screenshot 2026-04-17 144614" src="https://github.com/user-attachments/assets/9aca8e27-7ae1-44f1-bca2-cf5d4c98d84e" />
) |

---

## 🧠 How It Works

1. **Feature Engineering:** Extracts 15+ syntactic features from the URL (length, dots, hyphens, special characters, HTTPS presence, subdomain count, etc.).
2. **Classification:** A **LightGBM** model (trained on 30k+ URLs) predicts the class and confidence scores.
3. **Explanation (XAI):** **LIME** perturbs the input features and observes how predictions change, generating an intuitive HTML report that highlights feature contributions.

---

## 🛠️ Tech Stack

| Component               | Technology                     |
|:------------------------|:-------------------------------|
| Frontend & Backend      | Streamlit                      |
| Machine Learning        | LightGBM, Scikit-learn         |
| Explainable AI (XAI)    | LIME                           |
| Deployment              | Streamlit Cloud                |
| Data Processing         | Pandas, NumPy                  |
| Feature Extraction      | Python `urlparse`, Regex       |

---

## 🚀 Getting Started (Run Locally)

```bash
# 1. Clone the repository
git clone https://github.com/mdimteyazhossen/Malicious-Detective-XAI.git
cd Malicious-Detective-XAI

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the Streamlit app
streamlit run app.py

...

---

## 🔒 Educational Purpose Only

This tool is developed strictly for **educational and research purposes**. It demonstrates how machine learning and explainable AI can be applied to cybersecurity threat detection. **Do not use this tool for any malicious or unlawful activities.** The developer assumes no responsibility for misuse.

---
