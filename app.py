import streamlit as st
import pickle
from lime.lime_text import LimeTextExplainer
import streamlit.components.v1 as components

#PAGE CONFIGURATION
st.set_page_config(
    page_title="SpamShield XAI",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed"
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
        .main-header {
            font-size: 2rem !important;
        }
        .sub-header {
            font-size: 0.9rem !important;
        }
        .stButton button {
            font-size: 16px !important;
            padding: 10px 0 !important;
        }
    }
</style>
""", unsafe_allow_html=True)
#CUSTOM CSS FOR AESTHETICS
st.markdown("""
<style>
    .main-header {
        text-align: center;
        padding: 1rem 0;
        background: linear-gradient(90deg, #1E3A8A 0%, #3B82F6 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 2.8rem;
        font-weight: 800;
        margin-bottom: 0;
    }
    .sub-header {
        text-align: center;
        color: #64748B;
        font-size: 1.1rem;
        margin-top: -10px;
        margin-bottom: 30px;
    }
    .stTextArea textarea {
        border-radius: 12px;
        border: 2px solid #E2E8F0;
        font-size: 16px;
        padding: 15px;
    }
    .stTextArea textarea:focus {
        border-color: #3B82F6;
        box-shadow: 0 0 0 2px rgba(59,130,246,0.2);
    }
    .stButton button {
        width: 100%;
        border-radius: 40px;
        background: linear-gradient(90deg, #1E3A8A 0%, #2563EB 100%);
        color: white;
        font-weight: 600;
        font-size: 18px;
        padding: 12px 0;
        border: none;
        transition: all 0.3s ease;
    }
    .stButton button:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 16px rgba(30,58,138,0.3);
    }
    .result-box {
        border-radius: 16px;
        padding: 20px;
        margin-top: 20px;
        text-align: center;
    }
    .spam-box {
        background-color: #FEF2F2;
        border-left: 6px solid #DC2626;
    }
    .ham-box {
        background-color: #F0FDF4;
        border-left: 6px solid #16A34A;
    }
    .footer {
        text-align: center;
        margin-top: 40px;
        color: #94A3B8;
        font-size: 0.9rem;
    }
    .metric-card {
        background: #F8FAFC;
        border-radius: 12px;
        padding: 10px 20px;
        margin: 10px 0;
    }
</style>
""", unsafe_allow_html=True)

#LOAD MODEL & VECTORIZER
@st.cache_resource
def load_assets():
    with open('spam_model.pkl', 'rb') as f:
        model = pickle.load(f)
    with open('vectorizer.pkl', 'rb') as f:
        vectorizer = pickle.load(f)
    return model, vectorizer

model, vectorizer = load_assets()

#lime explainer
@st.cache_resource
def get_explainer():
    return LimeTextExplainer(class_names=['Ham (safe)','Spam'])

explainer = get_explainer()

#UI HEADER
st.markdown('<div class="main-header">🛡️ SpamShield XAI</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">>AI-powered email threat detection · Built with Naive Bayes & Explainable AI (LIME)</div>', unsafe_allow_html=True)

#INPUT SECTION
st.markdown("### 📧 Paste Email Content")
user_input = st.text_area(
    label="Email body text",
    placeholder="e.g. \"Congratulations! You've won a free iPhone. Click here to claim your prize...\"",
    height=180,
    label_visibility="collapsed"
)

#ACTION BUTTON
col1, col2, col3 = st.columns([1, 2, 1])
with col2:
    analyze_btn = st.button("🔍 Analyze Email", use_container_width=True)

#RESULT DISPLAY
if analyze_btn:
    if user_input.strip():
        with st.spinner("Scanning for threats..."):
            transformed = vectorizer.transform([user_input])
            prediction = model.predict(transformed)[0]
            proba = model.predict_proba(transformed)[0]

        spam_prob = proba[1] * 100
        ham_prob = proba[0] * 100

        if prediction == 1:
            st.markdown("""
            <div class="result-box spam-box">
                <h2 style="color: #DC2626; margin-bottom: 10px;">🚨 SPAM DETECTED</h2>
                <p style="font-size: 1.1rem; color: #7F1D1D;">This email appears to be unsolicited or malicious.</p>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="result-box ham-box">
                <h2 style="color: #16A34A; margin-bottom: 10px;">✅ SAFE (HAM)</h2>
                <p style="font-size: 1.1rem; color: #14532D;">This email looks legitimate.</p>
            </div>
            """, unsafe_allow_html=True)

        col1, col2 = st.columns(2)
        with col1:
            st.metric("🔴 Spam Probability", f"{spam_prob:.2f}%")
        with col2:
            st.metric("🟢 Ham Probability", f"{ham_prob:.2f}%")

        with st.expander("📊 Model Insight"):
            st.write(f"- **Classifier:** Multinomial Naive Bayes")
            st.write(f"- **Vectorizer:** CountVectorizer (bag-of-words)")
            st.write(f"- **Confidence Threshold:** 50%")
            st.caption("The model analyzes word frequencies and patterns associated with spam emails.")
        #lime explanation
        def predict_proba(texts):
            transformed = vectorizer.transform(texts)
            return model.predict_proba(transformed)
        with st.spinner("🔍 Explaining the prediction..."):
            exp = explainer.explain_instance(user_input, predict_proba, num_features=10)
        st.subheader("🔍 Why this prediction?")
        components.html(exp.as_html(),height=400, scrolling=True)
        st.caption("🟢 Green words = Ham (Safe) | 🔴 Red words = Spam")
    else:
        st.warning("⚠️ Please paste some email content to analyze.")

#FOOTER
st.markdown("---")
st.markdown(
    '<div class="footer">Built by Md Imteyaz Hossen · '
    'Cyber + AI Portfolio · '
    '<a href="https://github.com/mdimteyazhossen" target="_blank">GitHub</a> · '
    '<a href="https://www.kaggle.com/mdimteyazhossen" target="_blank">Kaggle</a></div>',
    unsafe_allow_html=True
)



