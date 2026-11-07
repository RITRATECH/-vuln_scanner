import streamlit as st
from scanner import run_scan
from datetime import datetime
import plotly.graph_objects as go

st.set_page_config(
    page_title="🛡️ Vulnerability Scanner",
    layout="wide",
    initial_sidebar_state="expanded"
)

# === Sidebar untuk Input ===
st.sidebar.title("🔍 Scan Target")
url = st.sidebar.text_input("🌐 Masukkan URL target", "https://idwebhost.com")
ip = st.sidebar.text_input("🧠 Masukkan IP target", "172.67.70.202")
scan_button = st.sidebar.button("🚀 Mulai Scan")

st.title("🛡️ Simple Vulnerability Scanner")
st.markdown("Versi GUI | by `SIBERAI`")

# === Jalankan scan saat tombol ditekan ===
if scan_button:
    with st.spinner("🔎 Sedang melakukan scanning..."):
        results = run_scan(url, ip)

    st.success("✅ Scan selesai!")
    st.markdown(f"🕒 Waktu scan: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`")
    st.markdown(f"📌 Target: `{url}` | 🧠 IP: `{ip}`")

    # === Tampilkan hasil ===
    st.markdown("---")
    st.subheader("📊 Hasil Scan")

    col1, col2 = st.columns(2)

    with col1:
        st.info(f"**Status Code:** `{results['status_code']}`")
        st.info(f"**Server:** `{results['server']}`")

        st.markdown("### ⚠️ Header Issues")
        if results['header_issues'] != "None":
            for issue in results['header_issues'].split(";"):
                if "Missing" in issue:
                    st.error("❌ " + issue.strip())
                elif "reveals" in issue:
                    st.warning("⚠️ " + issue.strip())
        else:
            st.success("✅ Semua header aman.")

        st.markdown("### 🧭 Path Ditemukan")
        if results['vulnerable_paths'] != "-":
            for path in results['vulnerable_paths'].split(","):
                st.warning(path.strip())
        else:
            st.success("✅ Tidak ada path umum terbuka.")

    with col2:
        st.markdown("### 🧪 Hasil XSS/SQLi")
        if results['xss_sqli_results'] != "None":
            for vuln in results['xss_sqli_results'].split(";"):
                st.error("❌ " + vuln.strip())
        else:
            st.success("✅ Tidak ada XSS/SQLi terdeteksi.")

        st.markdown("### 📡 Banner Grabbing")
        st.markdown("**HTTP Banner:**")
        st.code(results["banner_http"], language="bash")
        st.markdown("**HTTPS Banner:**")
        st.code(results["banner_https"], language="bash")

    st.markdown("---")
    st.subheader("📊 Statistik Hasil Scan")

    # Pie Chart: Header Security
    header_issues = results['header_issues'].split(";") if results['header_issues'] != "None" else []
    pie_labels = ['Aman', 'Bermasalah']
    pie_values = [4 - len(header_issues), len(header_issues)]  # total 4 header dicek

    pie_fig = go.Figure(data=[go.Pie(labels=pie_labels, values=pie_values, hole=0.4)])
    pie_fig.update_layout(title_text="Keamanan Header")

    # Bar Chart: Jumlah temuan
    vuln_paths = 0 if results['vulnerable_paths'] == "-" else len(results['vulnerable_paths'].split(","))
    xss_sqli = 0 if results['xss_sqli_results'] == "None" else len(results['xss_sqli_results'].split(";"))

    bar_fig = go.Figure(data=[
        go.Bar(name='Path Terbuka', x=['Temuan'], y=[vuln_paths], marker_color='orange'),
        go.Bar(name='XSS/SQLi', x=['Temuan'], y=[xss_sqli], marker_color='red')
    ])
    bar_fig.update_layout(barmode='group', title_text='Temuan Vuln')

    # Tampilkan grafik
    st.plotly_chart(pie_fig, use_container_width=True)
    st.plotly_chart(bar_fig, use_container_width=True)

    # === Tombol Download CSV ===
    st.markdown("---")
    with open("scan_results.csv", "rb") as f:
        st.download_button("📥 Download hasil CSV", f, file_name="scan_results.csv")

    # === Credit & Footer ===
    st.markdown("<center>🛠️ Dibuat oleh: <strong>SIBERAI</strong> | Powered by <code>Python + Streamlit</code></center>", unsafe_allow_html=True)

# === Hacker-style CSS & Background Animation ===
st.markdown("""
<style>
body {
    background-color: #0f1117;
    color: #00FF00;
    font-family: 'Courier New', monospace !important;
}
.stButton>button {
    background-color: #1f1f1f;
    color: #00FF00;
    border: 1px solid #00FF00;
    padding: 10px 20px;
    font-size: 16px;
}
.stTextInput>div>div>input {
    background-color: #1c1c1c;
    color: #00FF00;
    border: 1px solid #00FF00;
}
h1, h2, h3 {
    color: #00FF00;
}
.reportview-container .main .block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
    padding-left: 5rem;
    padding-right: 5rem;
}
body::before {
    content: "";
    position: fixed;
    top: 0;
    left: 0;
    width: 100vw;
    height: 100vh;
    background-image: url('https://media.giphy.com/media/E1ktykzzgKZqk/giphy.gif');
    background-size: cover;
    opacity: 0.03;
    z-index: -1;
}
</style>
""", unsafe_allow_html=True)
