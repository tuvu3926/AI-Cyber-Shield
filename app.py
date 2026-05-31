# ============================================================
# AI CYBER SHIELD - PHISHING DETECTION DASHBOARD
# RANDOM FOREST + NAIVE BAYES
# ============================================================

# =========================
# IMPORT LIBRARIES
# =========================
import streamlit as st
import pandas as pd
import numpy as np
import joblib
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
from feature_extractor import URLFeatureExtractor
import warnings


warnings.filterwarnings("ignore")
import os

HISTORY_FILE = "scan_history.csv"

if not os.path.exists(HISTORY_FILE):
    pd.DataFrame(columns=[
        "url",
        "forest_result",
        "forest_risk",
        "bayes_result",
        "bayes_risk",
        "final_result",
        "time"
    ]).to_csv(HISTORY_FILE, index=False)
# =========================
# PAGE CONFIG
# =========================
st.set_page_config(
    page_title="AI Cyber Shield",
    page_icon="🛡️",
    layout="wide"
)

# =========================
# CUSTOM CSS
# =========================
st.markdown("""
<style>

.main {
    background-color: #0E1117;
}

.stButton > button {
    width: 100%;
    height: 3em;
    border-radius: 10px;
    background-color: #00ADB5;
    color: white;
    font-weight: bold;
    font-size: 18px;
}

.result-safe {
    background-color: rgba(0,255,0,0.15);
    padding: 20px;
    border-radius: 12px;
    color: #00FF7F;
    font-size: 22px;
    text-align: center;
    font-weight: bold;
}

.result-phishing {
    background-color: rgba(255,0,0,0.15);
    padding: 20px;
    border-radius: 12px;
    color: #FF4B4B;
    font-size: 22px;
    text-align: center;
    font-weight: bold;
}

</style>
""", unsafe_allow_html=True)

# =========================
# DATABASE
# =========================

# =========================
# LOAD MODELS
# =========================
@st.cache_resource
def load_models():

    # RANDOM FOREST
    rf_data = joblib.load("best_model.pkl")
    rf_model = rf_data['model']
    columns = rf_data['feature_columns']

    # NAIVE BAYES
    nb_data = joblib.load("naive_bayes_model.pkl")
    nb_model = nb_data['model']

    return rf_model, nb_model, columns

rf_model, nb_model, columns = load_models()

# =========================
# FEATURE EXTRACTOR
# =========================
extractor = URLFeatureExtractor(
    top_domains_file="top_10000_domains.csv"
)

# =========================
# SIDEBAR
# =========================
st.sidebar.title("🛡️ AI CYBER SHIELD")

menu = st.sidebar.radio(
    "Navigation",
    [
        "🔍 URL Scanner",
        "📊 Analytics",
        "📈 Model Performance",
        "📑 Scan History",
        "⚙️ Feature Info",
        "ℹ️ About"
    ]
)

# ============================================================
# URL SCANNER
# ============================================================
if menu == "🔍 URL Scanner":

    st.title("🛡️ AI Phishing Detection Dashboard")

    st.markdown("""
    ### 🔥 Advanced URL Security Scanner

    Detect phishing URLs using:

    - 🌲 Random Forest
    - 📘 Naive Bayes
    - 📊 Feature Engineering
    - ⚡ Real-time URL Analysis
    """)

    st.markdown("---")

    url = st.text_input(
        "🔗 Enter URL",
        placeholder="https://example.com"
    )

    analyze_btn = st.button("🚀 Analyze URL")

    if analyze_btn:

        if url == "":
            st.warning("Please enter a URL")
            st.stop()

        with st.spinner("Analyzing URL..."):

            try:

                # =========================
                # EXTRACT FEATURES
                # =========================
                features = extractor.extract_features(url)

                feature_df = pd.DataFrame(
                    [features],
                    columns=columns
                )

                # ====================================================
                # RANDOM FOREST
                # ====================================================
                rf_probs = rf_model.predict_proba(feature_df)[0]
                rf_classes = list(rf_model.classes_)

                if -1 in rf_classes:
                    rf_idx = rf_classes.index(-1)
                    rf_risk = rf_probs[rf_idx]
                else:
                    rf_risk = 0

                rf_result = (
                    "PHISHING"
                    if rf_risk >= 0.85
                    else "LEGITIMATE"
                )

                # ====================================================
                # NAIVE BAYES
                # ====================================================
                nb_probs = nb_model.predict_proba(feature_df)[0]
                nb_classes = list(nb_model.classes_)

                if -1 in nb_classes:
                    nb_idx = nb_classes.index(-1)
                    nb_risk = nb_probs[nb_idx]
                else:
                    nb_risk = 0

                nb_result = (
                    "PHISHING"
                    if nb_risk >= 0.85
                    else "LEGITIMATE"
                )
                # ====================================================
                # FINAL VERDICT
                # ====================================================

                avg_risk = (rf_risk + nb_risk) / 2

                if rf_result == "PHISHING" and nb_result == "PHISHING":

                    final_result = "HIGH RISK"

                elif rf_result == "PHISHING" or nb_result == "PHISHING":

                    final_result = "MEDIUM RISK"

                else:

                    final_result = "SAFE"

                # =========================
                # SAVE HISTORY
                # =========================
                new_record = pd.DataFrame([{
                    "url": url,
                    "forest_result": rf_result,
                    "forest_risk": round(rf_risk * 100, 2),
                    "bayes_result": nb_result,
                    "bayes_risk": round(nb_risk * 100, 2),
                    "final_result": final_result,
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }])

                history = pd.read_csv(HISTORY_FILE)

                history = pd.concat(
                    [history, new_record],
                    ignore_index=True
                )

                history.to_csv(
                    HISTORY_FILE,
                    index=False
                )
                # ====================================================
                # RESULTS
                # ====================================================
                col1, col2 = st.columns(2)

                # RANDOM FOREST
                with col1:

                    st.subheader("🌲 Random Forest")

                    if rf_result == "PHISHING":

                        st.markdown(f"""
                        <div class="result-phishing">
                        ⚠️ PHISHING DETECTED
                        <br><br>
                        Risk Score: {rf_risk*100:.2f}%
                        </div>
                        """, unsafe_allow_html=True)

                    else:

                        st.markdown(f"""
                        <div class="result-safe">
                        ✅ LEGITIMATE WEBSITE
                        <br><br>
                        Risk Score: {rf_risk*100:.2f}%
                        </div>
                        """, unsafe_allow_html=True)

                # NAIVE BAYES
                with col2:

                    st.subheader("📘 Naive Bayes")

                    if nb_result == "PHISHING":

                        st.markdown(f"""
                        <div class="result-phishing">
                        ⚠️ PHISHING DETECTED
                        <br><br>
                        Risk Score: {nb_risk*100:.2f}%
                        </div>
                        """, unsafe_allow_html=True)

                    else:

                        st.markdown(f"""
                        <div class="result-safe">
                        ✅ LEGITIMATE WEBSITE
                        <br><br>
                        Risk Score: {nb_risk*100:.2f}%
                        </div>
                        """, unsafe_allow_html=True)

                st.markdown("---")

                st.subheader("🤖 AI Final Verdict")

                if final_result == "HIGH RISK":

                    st.error(
                        f"""
                🚨 HIGH RISK PHISHING WEBSITE

                Average Risk Score: {avg_risk*100:.2f}%

                Both AI models classified this URL as phishing.
                """
                    )

                elif final_result == "MEDIUM RISK":

                    st.warning(
                        f"""
                ⚠️ MEDIUM RISK

                Average Risk Score: {avg_risk*100:.2f}%

                One AI model detected suspicious behaviour.
                """
                    )

                else:

                    st.success(
                        f"""
                ✅ SAFE WEBSITE

                Average Risk Score: {avg_risk*100:.2f}%

                Both AI models classified this URL as legitimate.
                """
                    )

                st.markdown("---")

                # ====================================================
                # FEATURE ANALYSIS
                # ====================================================
                st.subheader("📊 Extracted Features")

                feature_vis = pd.DataFrame({
                    "Feature": columns,
                    "Value": features
                })

                fig = px.bar(
                    feature_vis,
                    x="Feature",
                    y="Value",
                    title="Feature Analysis"
                )

                st.plotly_chart(
                    fig,
                    use_container_width=True
                )

            except Exception as e:
                st.error(f"Error: {e}")

# ============================================================
# ANALYTICS
# ============================================================
elif menu == "📊 Analytics":

    st.title("📊 Dashboard Analytics")

    try:
        history = pd.read_csv(HISTORY_FILE)
    except Exception as e:
        st.error(f"Database Error: {e}")
        history = pd.DataFrame()

    if len(history) == 0:
        st.warning("No scan history available")
        st.stop()

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Total Scans", len(history))

    with col2:
        phishing_count = len(
            history[
                history["forest_result"] == "PHISHING"
            ]
        )

        st.metric(
            "Forest Phishing",
            phishing_count
        )

    with col3:
        legit_count = len(
            history[
                history["forest_result"] == "LEGITIMATE"
            ]
        )

        st.metric(
            "Forest Legitimate",
            legit_count
        )

    st.markdown("---")

    fig = px.pie(
        history,
        names="forest_result",
        title="Random Forest Distribution"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

# ============================================================
# MODEL PERFORMANCE
# ============================================================
elif menu == "📈 Model Performance":

    st.title("📈 Model Performance")

    st.markdown("## 📄 Accuracy & Recall Results")

    try:

        # LOAD CSV
        result_df = pd.read_csv("ket_qua_so_sanh.csv")

        # SHOW TABLE
        st.dataframe(
            result_df,
            use_container_width=True
        )

        st.markdown("---")

        # BAR CHART
        if (
            "Model" in result_df.columns
            and "Accuracy" in result_df.columns
        ):

            metric_cols = []

            if "Accuracy" in result_df.columns:
                metric_cols.append("Accuracy")

            if "Recall" in result_df.columns:
                metric_cols.append("Recall")

            chart_df = result_df.melt(
                id_vars="Model",
                value_vars=metric_cols,
                var_name="Metric",
                value_name="Score"
            )

            fig = px.bar(
                chart_df,
                x="Model",
                y="Score",
                color="Metric",
                barmode="group",
                title="Accuracy & Recall Comparison"
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

    except Exception as e:

        st.error(f"Cannot load ket_qua_so_sanh.csv: {e}")
        # ==================================
    # FEATURE IMPORTANCE
    # ==================================
    st.markdown("## 🔥 Top 10 Important Features")

    try:

        st.image(
            "10dactrungquantrong.png",
            caption="Top 10 Important Features",
            use_container_width=True
        )

    except Exception as e:

        st.warning(
            f"Cannot load image 10dactrungquantrong.png: {e}"
        )

    st.markdown("---")

    # ==================================
    # CONFUSION MATRIX
    # ==================================
    st.markdown("## 🎯 Confusion Matrix")

    try:

        st.image(
            "matrannhamlan.png",
            caption="Confusion Matrix",
            use_container_width=True
        )

    except Exception as e:

        st.warning(
            f"Cannot load image matrannhamlan.png: {e}"
        )

# ============================================================
# HISTORY
# ============================================================
elif menu == "📑 Scan History":

    st.title("📑 Scan History")

    # =========================
    # SESSION STATE
    # =========================
    if "confirm_delete" not in st.session_state:
        st.session_state.confirm_delete = False

    # =========================
    # DELETE BUTTON
    # =========================
    col1, col2 = st.columns([1, 4])

    with col1:
        if st.button("Clear History"):
            st.session_state.confirm_delete = True

    # =========================
    # CONFIRM DELETE
    # =========================
    if st.session_state.confirm_delete:

        st.warning(
            "⚠️ Are you sure you want to permanently delete all scan history?"
        )

        c1, c2 = st.columns(2)

        with c1:
            if st.button("✅ Yes, Delete All"):

                try:
                    pd.DataFrame(columns=[
                        "url",
                        "forest_result",
                        "forest_risk",
                        "bayes_result",
                        "bayes_risk",
                        "final_result",
                        "time"
                    ]).to_csv(HISTORY_FILE, index=False)

                    st.success("History cleared")

                except Exception as e:
                    st.error(f"Delete Error: {e}")

                st.session_state.confirm_delete = False

                st.success(
                    "✅ All scan history has been deleted."
                )

                st.rerun()

        with c2:
            if st.button("❌ Cancel"):

                st.session_state.confirm_delete = False
                st.rerun()

    st.markdown("---")

    # =========================
    # LOAD HISTORY
    # =========================
    try:
        history = pd.read_csv(HISTORY_FILE)

        if not history.empty:
            history = history.iloc[::-1]

    except Exception as e:
        st.error(f"History Error: {e}")
        history = pd.DataFrame()

    if len(history) == 0:
        st.info("No scan history available.")
    else:
        st.dataframe(
            history,
            use_container_width=True
        )

# ============================================================
# FEATURE INFO
# ============================================================
elif menu == "⚙️ Feature Info":

    st.title("⚙️ URL Feature Information")

    feature_data = [
        ["having_IP_Address", "Checks if URL uses an IP address", "URL-Based"],
        ["URL_Length", "Long URLs are suspicious", "URL-Based"],
        ["Shortining_Service", "Detects URL shortening services", "URL-Based"],
        ["having_At_Symbol", "Checks for '@' symbol", "URL-Based"],
        ["double_slash_redirecting", "Detects suspicious redirects", "URL-Based"],
        ["Prefix_Suffix", "Checks for '-' in domain", "Domain-Based"],
        ["having_Sub_Domain", "Analyzes subdomain count", "Domain-Based"],
        ["SSLfinal_State", "HTTPS validation", "Security"],
        ["Domain_registeration_length", "Remaining domain registration period", "Domain-Based"],
        ["HTTPS_token", "Detects fake HTTPS in domain", "Security"],
        ["Abnormal_URL", "Abnormal URL detection", "URL-Based"],
        ["port", "Checks non-standard ports", "Network"],

        ["Favicon", "External favicon detection", "HTML-Based"],
        ["Request_URL", "External resource requests", "HTML-Based"],
        ["URL_of_Anchor", "Unsafe anchor links", "HTML-Based"],
        ["Links_in_tags", "External scripts/resources", "HTML-Based"],
        ["SFH", "Form handler analysis", "HTML-Based"],
        ["Submitting_to_email", "Form submits to email", "HTML-Based"],
        ["Redirect", "Redirect chain analysis", "HTML-Based"],
        ["on_mouseover", "Mouse-over script detection", "JavaScript"],
        ["RightClick", "Right-click disabling detection", "JavaScript"],
        ["popUpWindow", "Popup window detection", "JavaScript"],
        ["Iframe", "Iframe detection", "HTML-Based"],

        ["Links_pointing_to_page", "Backlink trust analysis", "Reputation"],
        ["age_of_domain", "Domain age analysis", "Domain-Based"],
        ["dns_record", "DNS record existence", "Network"],
        ["web_traffic", "Website popularity", "Reputation"],
        ["google_index", "Google indexing status", "Reputation"],
        ["statistical_report", "Statistical reputation feature", "Reputation"]
    ]

    info_df = pd.DataFrame(
        feature_data,
        columns=["Feature", "Description", "Category"]
    )

    st.dataframe(
        info_df,
        use_container_width=True
    )

# ============================================================
# ABOUT
# ============================================================
elif menu == "ℹ️ About":

    st.title("ℹ️ About Project")

    st.markdown("""
    ## 🛡️ AI CYBER SHIELD

    Advanced phishing detection system using:

    - 🌲 Random Forest
    - 📘 Naive Bayes
    - 📊 Feature Engineering
    - ⚡ Real-time URL Analysis

    ## 🚀 Features

    ✅ Dual AI Models
    ✅ Random Forest Detection
    ✅ Naive Bayes Detection
    ✅ Analytics Dashboard
    ✅ Model Performance CSV
    ✅ Scan History
    ✅ CSV History Storage
    ✅ Real-time Detection

    ## 👨‍💻 Technologies

    - Python
    - Streamlit
    - Scikit-learn
    - Plotly
    - Pandas
    - CSV Storage
    """)