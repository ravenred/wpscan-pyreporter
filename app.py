import streamlit as st
from src.components import parser

st.title("wpscan - Reporter")
st.text("Description of what this is......")

st.header("Upload wpscan JSON")
upload_file = st.file_uploader("Choose a JSON file",
                               type=["json"])
st.divider()
if upload_file is not None:
    st.write(f'You Uploaded - {upload_file.name}')
    host, df_wordpress_version, df_plugins, df_users, df_interesting_findings, df_themes, df_vulnerabilities \
        = parser.load_wpscan_json(upload_file)
    st.header("Host Details", divider=True)
    st.write("Host URL: " + host)
    st.divider()
    st.header("Vulnerabilities", divider=True)
    total, wv, pv, tv = st.columns(4)
    total.metric(label="Total Vulnerabilities", value=df_vulnerabilities.shape[0], border=True)
    wv.metric(label="Wordpress Vulnerabilities", value=df_vulnerabilities.component.str.count("WordPress").sum(),
              border=True)
    pv.metric(label="Plugins Vulnerabilities", value=df_vulnerabilities.component.str.count("Plugin").sum(),
              border=True)
    tv.metric(label="Themes Vulnerabilities", value=df_vulnerabilities.component.str.count("Themes").sum(),
              border=True)
    st.divider()
    st.subheader("Vulnerabilities Breakdown", divider=True)
    st.dataframe(df_vulnerabilities, hide_index=True)

    st.header("Findings Breakdown", divider=True)
    plugins, users, interesting_findings = st.columns(3)
    plugins.metric(label="Plugins", value=df_plugins.shape[0], delta=0,border=True)
    users.metric(label="Users", value=df_users.shape[0], delta=0, border=True)
    interesting_findings.metric(label="Interesting Findings", value=df_interesting_findings.shape[0],
                                delta=0, border=True)
    st.subheader("Plugins Discovered", divider=True)
    st.dataframe(df_plugins, hide_index=True)
    st.subheader("Users Discovered", divider=True)
    st.dataframe(df_users, hide_index=True)
    st.subheader("Interesting Findings", divider=True)
    st.dataframe(df_interesting_findings, hide_index=True)


