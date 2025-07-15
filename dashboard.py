# ---
# jupyter:
#   jupytext:
#     text_representation:
#       extension: .py
#       format_name: percent
#       format_version: '1.3'
#       jupytext_version: 1.17.2
#   kernelspec:
#     display_name: Python 3 (ipykernel)
#     language: python
#     name: python3
# ---

# %%
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from io import StringIO
from main import *
from fpdf import FPDF
import os

@st.cache_resource
def load_trained_model():
    return joblib.load("isolation_forest_model.pkl")

def main():
    # Streamlit settings
    st.set_page_config(page_title="BreachLens Dashboard", layout="wide")
    
    st.title("🛡️ BreachLens - Forensic Log Analysis")
    st.subheader("Upload Apache/Nginx logs, detect anomalies, visualize attack patterns, and generate reports.")
    
    # Upload Section
    with st.expander("📁 Upload Log File", expanded=True):
        uploaded_file = st.file_uploader("Upload Apache/Nginx log file", type=["log", "txt"])
        if uploaded_file:
            content = uploaded_file.read().decode("utf-8")
            temp_log_path = "uploaded_access_log.log"
            with open(temp_log_path, "w") as f:
                f.write(content)
    
            st.success("Log file uploaded successfully.")
    
            session_df, sessions = parse_log_file(temp_log_path)
            final_sessions = sessionIdentification(sessions)
            final_df = build_final_dataframe(final_sessions, log_pattern, parse_time)
    
            # Feature Engineering
            session_df = add_ip_frequency(session_df)
            session_df = add_url_length(session_df)
            session_df, le = encode_request_method(session_df)
            session_df = add_hour_from_timestamp(session_df)
            session_df = add_referrer_length(session_df)
    
            feature_cols = ['ip_freq', 'size', 'url_length', 'status', 'method_encoded', 'hour', 'referrer_length']
            X_scaled, scaler = prepare_isolation_forest_features(session_df, feature_cols)
    
            model = load_trained_model()
            session_df = predict_anomaly(session_df, model, feature_cols, scaler=scaler, label_encoder=le)

    
    # Detection Section
    if uploaded_file:
        with st.expander("🚨 Anomaly & Threat Detection", expanded=True):
    
            # 1. Isolation Forest
            st.subheader("📉 Isolation Forest Anomalies")
            if 'is_anomaly' in session_df.columns:
                st.write(f"Detected {sum(session_df['is_anomaly'] == -1)} anomalies")
                st.dataframe(session_df[session_df['is_anomaly'] == -1])
            else:
                st.warning("'is_anomaly' column missing in session_df")
    
            # 2. Zero-Day and Multi-Phase
            st.subheader("🕵️ Zero-Day Signatures & Multi-Phase Behavior")
            anomaly_results = detect_zero_day_anomalies(session_df)
            if anomaly_results and len(anomaly_results) >= 2:
                correlated_df = anomaly_results[1]
                if not correlated_df.empty:
                    multi_phase_ips = detect_multi_phase_behavior(correlated_df)
                    suspicious_ips = get_suspicious_ips(correlated_df, multi_phase_ips)
                    st.success(f"Detected {len(suspicious_ips)} suspicious IPs across phases.")
                    st.dataframe(correlated_df)
                else:
                    suspicious_ips = []
                    multi_phase_ips = []
                    st.warning("No zero-day correlated sessions found.")
            else:
                st.warning("Zero-day analysis failed.")
    
            st.subheader("🧠 Feature-Based Session Clustering (using DBSCAN)")
            try:
                features_df = enrich_error_logs_with_features(session_df)
            
                # Ensure all vectors are built from the same features_df
                X = hstack([
                    path_vectors[:features_df.shape[0]],
                    param_vectors[:features_df.shape[0]],
                    np.array(features_df['status']).reshape(-1, 1),
                    np.array(features_df['ip_freq']).reshape(-1, 1)
                ])
            
                labels, model = run_dbscan_clustering(X, eps=0.4, min_samples=5)
            
                features_df = add_cluster_labels(features_df, labels)
            
                clustered_errors = group_logs_by_cluster(features_df)
                cluster_summary = summarize_feature_clusters(features_df)
            
                if 'cluster' in features_df.columns and not cluster_summary.empty:
                    st.dataframe(cluster_summary.head())
                else:
                    st.warning("Cluster summary or labels not available.")
            except Exception as e:
                st.error(f"Error in clustering: {e}")


    
            # 4. IP Request Count Analysis
            st.subheader("🌐 Top IP Request Patterns")
            try:
                ip_freq_df = compute_ip_request_counts(session_df)
                st.dataframe(ip_freq_df)
                top_ips = get_top_ips(ip_freq_df, top_n=20)
                plot_top_ip_requests(top_ips)
            except Exception as e:
                st.error(f"Failed to compute: {e}")
    
            # 5. Error Log Features
            st.subheader("🚫 Error Logs")
            try:
                error_logs_df = filter_error_logs(final_df)
                enriched_errors = enrich_error_logs_with_features(error_logs_df)
                st.dataframe(enriched_errors)
            except Exception as e:
                st.error(f"Error enriching error logs: {e}")
    
    
            # 7. User-Agent Analysis
            st.subheader("🧬 User-Agent Fingerprinting")
            try:
                ua_df, suspicious_agents = analyze_user_agents(final_df['user_agent'])
                if ua_df is not None and not ua_df.empty:
                    st.dataframe(ua_df)
                else:
                    st.warning("User-Agent analysis returned no results.")
            except Exception as e:
                st.error(f"Error analyzing user-agents: {e}")

    
    # Timeline
        with st.expander("📊 Forensic Timeline"):
            st.subheader("📦 Abnormal Response Sizes")
            try:
                response_df = extract_response_sizes(final_df,final_sessions, log_pattern)
                if 'timestamp' in response_df.columns and 'response_size' in response_df.columns:
                    st.line_chart(response_df[['timestamp', 'response_size']].set_index('timestamp'))
                else:
                    st.warning("Required columns for plotting response sizes are missing.")
            except Exception as e:
                st.error(f"Error extracting response sizes: {e}")

            st.subheader("🧠 Feature-Based Session Clustering (using DBSCAN)")
            try:
                features_df = enrich_error_logs_with_features(session_df)
            
                # Ensure all vectors are built from the same features_df
                X = hstack([
                    path_vectors[:features_df.shape[0]],
                    param_vectors[:features_df.shape[0]],
                    np.array(features_df['status']).reshape(-1, 1),
                    np.array(features_df['ip_freq']).reshape(-1, 1)
                ])
            
                labels, model = run_dbscan_clustering(X, eps=0.4, min_samples=5)
            
                features_df = add_cluster_labels(features_df, labels)
            
                clustered_errors = group_logs_by_cluster(features_df)
                cluster_summary = summarize_feature_clusters(features_df)
            
                if 'cluster' in features_df.columns and not cluster_summary.empty:
                    st.bar_chart(features_df['cluster'].value_counts())
                else:
                    st.warning("Cluster summary or labels not available.")
            except Exception as e:
                st.error(f"Error in clustering: {e}")


            st.subheader("🌐 Top IP Request Patterns")
            try:
                ip_freq_df = compute_ip_request_counts(session_df)
                top_n = 20
                if top_n > ip_freq_df.shape[0]:
                    top_n = ip_freq_df.shape[0]
            
                top_ips = get_top_ips(ip_freq_df, top_n)
            
                # Set IP as index for bar_chart
                top_ips_chart = top_ips.set_index('IP')
                st.bar_chart(top_ips_chart['Request Count'])
            
            except Exception as e:
                st.error(f"Failed to compute: {e}")


            st.subheader("🧬 User-Agent Fingerprinting")
            try:
                ua_df, suspicious_agents = analyze_user_agents(final_df['user_agent'])
                if ua_df is not None and not ua_df.empty:
                    ua_df_sorted = ua_df.sort_values('Count', ascending=False).head(20)  # optional top N
                    st.bar_chart(ua_df_sorted.set_index('User-Agent')['Count'])
                else:
                    st.warning("User-Agent analysis returned no results.")
            except Exception as e:
                st.error(f"Error analyzing user-agents: {e}")

                    
            st.subheader("📈 Event Timeline")
            try:
                timelines = create_timelines(session_df)
                anomaly_timeline = timelines['anomaly']
                error_timeline = timelines['error']
                total_timeline = timelines['total']

                import pandas as pd
                timeline_df = pd.DataFrame({
                    'total_events': total_timeline,
                    'anomalies': anomaly_timeline,
                    'errors': error_timeline
                }).fillna(0)
            
                # Reset time_bin index to 'timestamp' column for line_chart
                timeline_df = timeline_df.reset_index().rename(columns={'time_bin': 'timestamp'})
            
                # Ensure timestamp is datetime and sorted
                if not pd.api.types.is_datetime64_any_dtype(timeline_df['timestamp']):
                    timeline_df['timestamp'] = pd.to_datetime(timeline_df['timestamp'], errors='coerce')
                timeline_df = timeline_df.sort_values('timestamp')
            
                # Set timestamp as index for line_chart
                timeline_df.set_index('timestamp', inplace=True)
            
                # Display interactive line chart
                st.line_chart(timeline_df)
            
            except Exception as e:
                st.error(f"Error plotting event timeline: {e}")
            
        
    # Suspicious IPs
        with st.expander("🌐 Suspicious IPs & WHOIS Lookup"):
        
            geo_df = geolocation(suspicious_ips,session_df,multi_phase_ips)
        
            if not geo_df.empty and {'lat', 'lon'}.issubset(geo_df.columns):
                st.success(f"Located {len(geo_df)} suspicious IPs on map.")
                st.map(geo_df.rename(columns={"lat": "latitude", "lon": "longitude"}))
            else:
                st.info("No suspicious IPs to mark.")
                # Show an empty map centered over a default region (e.g., Asia)
                import pandas as pd
                default_map_df = pd.DataFrame({"latitude": [20], "longitude": [80]})  # Centered over India
                st.map(default_map_df)
        
            if not geo_df.empty:
                st.dataframe(geo_df)
        
                region_summary = geo_df.groupby('country').size().reset_index(name='count')
                region_summary = region_summary.sort_values(by='count', ascending=False)
        
                st.subheader("🌍 Country-wise IP Distribution")
                st.bar_chart(region_summary.set_index('country'))
        
                if 'is_multi_phase' in geo_df.columns:
                    behavior_by_country = geo_df.groupby('country').agg({
                        'ip': 'count',
                        'is_multi_phase': 'sum'
                    }).rename(columns={'ip': 'unique_suspicious_ips', 'is_multi_phase': 'multi_phase_ips'})
        
                    st.subheader("🧠 Multi-Phase Behavior by Country")
                    st.dataframe(behavior_by_country.sort_values(by='unique_suspicious_ips', ascending=False))
        
            if suspicious_ips:
                selected_ip = st.selectbox("Investigate IP", list(suspicious_ips))
                if selected_ip:
                    whois_info = extract_whois_info(selected_ip, verbose=False)
                    st.json(whois_info)

        

    
    # File Integrity
        with st.expander("🗂️ File Integrity Check (Advanced)", expanded=False):
            suspected_dir = "suspected/"
            originals_dir = "originals/"
        
            if not os.path.exists(suspected_dir) or not os.path.exists(originals_dir):
                st.warning("Required folders 'suspected/' and 'originals/' are missing.")
            else:
                with st.spinner("Running file integrity analysis..."):
                    integrity_df = run_file_integrity_check(final_df)
                    st.success("File integrity check complete.")
                    st.dataframe(integrity_df)
        
                    tampered = integrity_df[integrity_df['integrity'] == 'Tampered']
                    missing = integrity_df[integrity_df['integrity'] == 'Missing']
        
                    st.write(f"🔴 Tampered Files: {len(tampered)}")
                    st.write(f"⚠️ Missing Files: {len(missing)}")
        
                    if not tampered.empty:
                        st.dataframe(tampered)
        
                    if not missing.empty:
                        st.dataframe(missing)
    
    
    # Filters
        with st.expander("🔎 Filter Logs"):
            required_cols = ['status', 'user_agent']
            if not all(col in session_df.columns for col in required_cols):
                st.error("Session data is missing required columns.")
            else:

                session_df['user_agent'] = session_df['user_agent'].fillna("Unknown")
                col1, col2 = st.columns(2)
                with col1:
                    selected_status = st.multiselect("Filter by Status", sorted(session_df['status'].unique()))
                with col2:
                    selected_agents = st.multiselect("Filter by User-Agent", session_df['user_agent'].unique())
        
                filtered_df = session_df.copy()
                if selected_status:
                    filtered_df = filtered_df[filtered_df['status'].isin(selected_status)]
                if selected_agents:
                    filtered_df = filtered_df[filtered_df['user_agent'].isin(selected_agents)]
        
                st.dataframe(filtered_df)
    
    # PDF Export
        with st.expander("📄 Export Forensic PDF Report"):
            if st.button("Generate PDF"):
                try:
                    from fpdf import FPDF
        
                    max_ips = 20
                    rule_based_ips = list(suspicious_ips)[:max_ips]
                    if 'is_anomaly' in session_df.columns and 'ip' in session_df.columns:
                        anomaly_ips = list(session_df[session_df['is_anomaly'] == -1]['ip'].unique())[:max_ips]
                    else:
                        anomaly_ips = []
                    
                    all_ips = list(set(rule_based_ips + anomaly_ips))

                    if not all_ips:
                        st.warning("No suspicious or anomalous IPs found to generate a report.")
                    else:
                        pdf = FPDF()
                        pdf.add_page()
                        pdf.set_font("Arial", size=12)
                        pdf.cell(200, 10, txt="BreachLens Forensic Report", ln=True, align="C")
        
                        pdf.ln(10)
                        pdf.set_font("Arial", size=10)
                        pdf.multi_cell(0, 5, txt=f"Total Suspicious IPs (Rule-based): {len(rule_based_ips)}")
                        pdf.multi_cell(0, 5, txt=f"Total Anomalous IPs (Isolation Forest): {len(anomaly_ips)}")
                        pdf.multi_cell(0, 5, txt=f"Total Unique IPs Reported: {len(all_ips)}\n\n")
        
                        # WHOIS Info
                        pdf.set_font("Arial", style='B', size=11)
                        pdf.cell(0, 5, "Top IP WHOIS Info", ln=True)
                        pdf.set_font("Arial", size=10)
        
                        for ip in all_ips[:5]:
                            info = extract_whois_info(ip, verbose=False)
                            org = info.get("organization", "N/A")
                            country = info.get("country", "N/A")
                            pdf.multi_cell(0, 5, txt=f"IP: {ip}\nOrg: {org}\nCountry: {country}\n")
        
                        # Log Entries
                        pdf.set_font("Arial", style='B', size=11)
                        pdf.cell(0, 8, "\nSample Suspicious Log Entries", ln=True)
                        pdf.set_font("Arial", size=10)
        
                        filtered_logs = session_df[session_df['ip'].isin(all_ips)]
                        cols_to_show = ['timestamp', 'ip', 'method', 'url', 'status']
                        expected_cols = set(cols_to_show)
        
                        if not filtered_logs.empty and expected_cols.issubset(filtered_logs.columns):
                            for _, row in filtered_logs[cols_to_show].head(10).iterrows():
                                entry = f"{row['timestamp']} | {row['ip']} | {row['method']} {row['url']} | {row['status']}"
                                pdf.multi_cell(0, 5, txt=str(entry))
                        else:
                            pdf.multi_cell(0, 5, txt="No matching session log entries found or required fields missing.")
        
                        # Export & Streamlit download
                        pdf.output("breachlens_report.pdf")
                        with open("breachlens_report.pdf", "rb") as f:
                            bytes_data = f.read()
        
                        st.download_button("📥 Download Report", bytes_data, file_name="breachlens_report.pdf")
        
                except Exception as e:
                    st.error(f"Failed to generate report: {e}")


    
    # Footer
    st.markdown("---")
    st.caption("Built with ❤️ by BreachLens • Powered by Machine Learning & Regex Forensics")
    

if __name__ == "__main__":
    main()