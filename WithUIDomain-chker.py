import os
import requests
import pandas as pd
import dns.resolver
import whois
from datetime import datetime
import streamlit as st

# Keywords to identify parked domains by NS
PARKING_KEYWORDS = [
    "parkingcrew", "sedoparking", "bodis", "afternic", "above", "uniregistry",
    "domaincontrol", "cashparking", "namebright", "namestore"
]

# Get expiration date via WHOIS
def get_expiration_date(domain):
    try:
        w = whois.whois(domain)
        exp_date = w.expiration_date
        if isinstance(exp_date, list):
            exp_date = exp_date[0]
        if isinstance(exp_date, datetime):
            return exp_date.strftime("%Y-%m-%d")
        return "Unknown"
    except Exception:
        return "Lookup Failed"

# Test domain HTTP(S) accessibility
def check_website(domain):
    urls = [f"http://{domain}", f"https://{domain}"]
    for url in urls:
        try:
            response = requests.get(url, timeout=5)
            if response.status_code < 400:
                return "Accessible"
        except requests.RequestException:
            continue
    return "Inaccessible"

# Get NS records
def get_name_servers(domain):
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        return sorted([str(r.target).strip('.') for r in answers])
    except Exception:
        return []

# Check if NS points to parked domain
def is_parking_ns(ns_records):
    return any(any(keyword in ns.lower() for keyword in PARKING_KEYWORDS) for ns in ns_records)

# Process a single domain (modified for progress feedback)
def process_single_domain(domain, check_expiry, check_ns, check_access):
    result = {"Domain": domain}

    if check_access:
        result["Status"] = check_website(domain)
    else:
        result["Status"] = "Skipped"

    if check_ns:
        ns_records = get_name_servers(domain)
        result["Name Servers"] = ", ".join(ns_records) if ns_records else "N/A"
        result["Possibly Parked"] = "Yes" if is_parking_ns(ns_records) else "No"
    else:
        result["Name Servers"] = "Skipped"
        result["Possibly Parked"] = "Skipped"

    if check_expiry:
        result["Expiration Date"] = get_expiration_date(domain)
    else:
        result["Expiration Date"] = "Skipped"

    return result

# Streamlit UI
def main():
    st.set_page_config(page_title="Domain Checker", layout="centered")
    st.title("🌐 Domain Status Checker")

    st.write("Select which checks to perform on each domain:")

    check_ns = st.checkbox("🔁 Name Server + Parking Detection", value=True)
    check_expiry = st.checkbox("📆 Expiration Date (WHOIS)", value=True)
    check_access = st.checkbox("🌍 Website Accessibility", value=True)

    st.markdown("### ✍️ Enter domain names (one per line):")
    domain_input = st.text_area("Domains", height=200, placeholder="example.com\nmydomain.net")

    if st.button("✅ Run Checks"):
        domains = [d.strip() for d in domain_input.splitlines() if d.strip()]
        if not domains:
            st.warning("Please input at least one domain.")
            return

        progress_bar = st.progress(0, text="Initializing...")
        results = []
        total = len(domains)

        for i, domain in enumerate(domains):
            percent = int((i + 1) / total * 100)
            progress_bar.progress(percent, text=f"Checking: {domain} ({percent}%)")

            result = process_single_domain(domain, check_expiry, check_ns, check_access)
            results.append(result)

        progress_bar.empty()

        df = pd.DataFrame(results)

        st.success("✅ Done!")
        st.dataframe(df)

        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button("📥 Download Results as CSV", csv, "domain_check_results.csv", "text/csv")

if __name__ == "__main__":
    main()
