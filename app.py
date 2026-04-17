import streamlit as st
import pickle
import re
import pandas as pd
import numpy as np
from urllib.parse import urlparse
from lime.lime_tabular import LimeTabularExplainer
import streamlit.components.v1 as components

st.set_page_config(
    page_title="Malicious Detective XAI",
    page_icon="🔍",
    layout="centered",
)

st.markdown("""
<style>
    iframe {
        background-color: white !important;
        border-radius: 12px !important;
        padding: 10px !important;
    }
    div[data-testid="stHtml"] {
        background-color: white !important;
        border-radius: 12px !important;
    }
    @media screen and (max-width: 600px) {
        .main-header { font-size: 2rem !important; }
        .sub-header { font-size: 0.9rem !important; }
        .stButton button { font-size: 16px !important; padding: 10px 0 !important; }
    }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<style>
    .main-header {
        text-align: center; padding: 1rem 0;
        background: linear-gradient(90deg, #DC2626 0%, #EA580C 100%);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        font-size: 2.8rem; font-weight: 800; margin-bottom: 0;
    }
    .sub-header {
        text-align: center; color: #94A3B8; font-size: 1.1rem;
        margin-top: -10px; margin-bottom: 30px;
    }
    .stTextInput > div > div > input {
        border-radius: 12px; border: 2px solid #334155;
        font-size: 16px; padding: 15px;
        background-color: #1E293B; color: white;
    }
    .stButton button {
        width: 100%; border-radius: 40px;
        background: linear-gradient(90deg, #DC2626 0%, #EA580C 100%);
        color: white; font-weight: 600; font-size: 18px;
        padding: 12px 0; border: none; transition: all 0.3s ease;
    }
    .stButton button:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 16px rgba(220, 38, 38, 0.3);
    }
    .result-box {
        border-radius: 16px; padding: 20px; margin-top: 20px; text-align: center;
    }
    .phishing-box {
        background-color: #FEF2F2; border-left: 6px solid #DC2626;
    }
    .malware-box {
        background-color: #FEFCE8; border-left: 6px solid #EAB308;
    }
    .benign-box {
        background-color: #F0FDF4; border-left: 6px solid #16A34A;
    }
    .footer {
        text-align: center; margin-top: 40px; color: #94A3B8; font-size: 0.9rem;
    }
    .footer a { color: #64748B; text-decoration: none; }
    .footer a:hover { color: #DC2626; }
</style>
""", unsafe_allow_html=True)

def extract_url_features(url):
    if not url:
        return None
    url = str(url).strip().lower()
    features = {}
    try:
        parsed = urlparse(url)
    except:
        return None
    hostname = parsed.netloc

    features['urlLength'] = len(url)
    features['hostLength'] = len(hostname)
    features['pathLength'] = len(parsed.path)
    features['count_dot'] = url.count('.')
    features['count-'] = url.count('-')
    features['count@'] = url.count('@')
    features['count?'] = url.count('?')
    features['count='] = url.count('=')
    features['count_digit'] = sum(c.isdigit() for c in url)
    features['has_https'] = 1 if parsed.scheme == 'https' else 0
    
    suspectionword = ['secure', 'account', 'confirm', 'login', 'signin', 'banking', 'verify', 'webscr']
    features['has_sus'] = 1 if any(word in url for word in suspectionword) else 0

    ipaddress = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    features['has_ipaddress'] = 1 if re.search(ipaddress, url) else 0

    if hostname:
        features['count_subdomain'] = len(hostname.split('.')) - 2
    else:
        features['count_subdomain'] = 0

    return features

@st.cache_resource
def load_assets():
    with open('urlModelLgb.pkl', 'rb') as f:
        model = pickle.load(f)
    with open('labelEncoder.pkl', 'rb') as f:
        le = pickle.load(f)
    with open('featuresNames.pkl', 'rb') as f:
        feature_names = pickle.load(f)
    xtrain = np.load('xtrain.npy')
    return model, le, feature_names, xtrain

model, le, feature_names, xtrain = load_assets()

@st.cache_resource
def get_explainer():
    return LimeTabularExplainer(
        training_data=xtrain,
        feature_names=feature_names,
        class_names=model.classes_,
        mode='classification'
    )

explainer = get_explainer()

st.markdown('<div class="main-header">🔍 Malicious Detective XAI</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Explainable AI for Phishing & Malware URL Detection</div>', unsafe_allow_html=True)

st.markdown("### 🔗 Enter URL to Analyze")
user_input = st.text_input(
    label="URL input",
    placeholder="https://example.com or http://suspicious-link.xyz",
    label_visibility="collapsed"
)

col1, col2, col3 = st.columns([1, 2, 1])
with col2:
    analyze_btn = st.button("🔎 Analyze URL", use_container_width=True)

if analyze_btn:
    if user_input.strip():
        with st.spinner("🔎 Analyzing URL..."):
            feats = extract_url_features(user_input)
            if feats is None:
                st.error("❌ Invalid URL format.")
            else:
                feat_df = pd.DataFrame([feats])
                feat_df = feat_df[feature_names]
                proba = model.predict_proba(feat_df)[0]
                pred_index = np.argmax(proba)
                pred_class = model.classes_[pred_index] 
                confidence = proba[pred_index]*100
                
                if pred_class == "Phishing":
                    st.markdown("""
                    <div class="result-box phishing-box">
                        <h2 style="color: #DC2626; margin-bottom: 8px;">🎣 PHISHING DETECTED</h2>
                        <p style="font-size: 1rem; color: #7F1D1D;">This URL is attempting to steal credentials.</p>
                    </div>
                    """, unsafe_allow_html=True)
                elif pred_class == "Malware":
                    st.markdown("""
                    <div class="result-box malware-box">
                        <h2 style="color: #EAB308; margin-bottom: 8px;">⚠️ MALWARE DETECTED</h2>
                        <p style="font-size: 1rem; color: #854D0E;">This URL hosts or distributes malicious software.</p>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown("""
                    <div class="result-box benign-box">
                        <h2 style="color: #16A34A; margin-bottom: 8px;">✅ SAFE (BENIGN)</h2>
                        <p style="font-size: 1rem; color: #14532D;">This URL appears to be legitimate.</p>
                    </div>
                    """, unsafe_allow_html=True)
                
                st.write(f"**Confidence:** {confidence:.2f}%")
                st.markdown("---")
                st.markdown("**📊 Class Probabilities:**")
                for i, cls in enumerate(model.classes_):
                    st.write(f"{cls}: {proba[i]*100:.2f}%")
                
                st.markdown("---")
                with st.spinner("🔬 Generating explanation with LIME..."):
                    exp = explainer.explain_instance(feat_df.values[0], model.predict_proba, num_features=10)
                st.subheader("🔬 Why this prediction?")
                components.html(exp.as_html(), height=400, scrolling=True)
                st.caption("🟢 Green = Supports Benign | 🔴 Red = Supports Phishing | 🟡 Yellow = Supports Malware")
    else:
        st.warning("⚠️ Please enter a URL.")

st.markdown("---")
st.markdown(
    '<div class="footer">Built by Md Imteyaz Hossen · '
    'Cyber + AI Portfolio · '
    '<a href="https://github.com/mdimteyazhossen" target="_blank">GitHub</a> · '
    '<a href="https://www.kaggle.com/mdimteyazhossen" target="_blank">Kaggle</a> · '
    '<a href="https://www.linkedin.com/in/mdimteyazhossen/" target="_blank">LinkedIn</a></div>',
    unsafe_allow_html=True
)
