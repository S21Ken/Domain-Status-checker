import os
import requests
import pandas as pd
import dns.resolver
import whois
from datetime import datetime
import streamlit as st

# Known parking-related keywords in name servers
PARKING_KEYWORDS = [
    "parkingcrew", "sedoparking", "bodis", "afternic", "above", "uniregistry",
    "domaincontrol", "cashparking", "namebright", "namestore"
]

HTTP_STATUS_DESCRIPTIONS = {
    200: "OK",
    301: "Moved Permanently",
    302: "Found (Redirect)",
    403: "Forbidden",
    404: "Not Found",
    500: "Internal Server Error"
}

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

# Get HTTP status and description
def check_http_status(domain):
    urls = [f"http://{domain}", f"https://{domain}"]
    for url in urls:
        try:
            response = requests.get(url, timeout=5)
            status = response.status_code
            description = HTTP_STATUS_DESCRIPTIONS.get(status, "Other")
            return f"{status} - {description}"
        except requests.RequestException:
            continue
    return "No Response"

# Get NS records
def get_name_servers(domain):
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        return sorted([str(r.target).strip('.') for r in answers])
    except Exception:
        return []

# Detect if NS is a parking provider
def check_if_parked(ns_records):
    return any(any(keyword in ns.lower() for keyword in PARKING_KEYWORDS) for ns in ns_records)

# Run selected checks on domain list
def process_domains(domains, check_expiry, check_ns, check_park, check_http):
    results = []

    for domain in domains:
        result = {"Domain": domain}

        if check_http:
            result["HTTP Status"] = check_http_status(domain)
        else:
            result["HTTP Status"] = "Skipped"

        if check_ns:
            ns_records = get_name_servers(domain)
            result["Name Servers"] = ", ".join(ns_records) if ns_records else "N/A"
        else:
            ns_records = []
            result["Name Servers"] = "Skipped"

        if check_park and ns_records:
            result["Possibly Parked"] = "Yes" if check_if_parked(ns_records) else "No"
        elif check_park:
            result["Possibly Parked"] = "N/A"
        else:
            result["Possibly Parked"] = "Skipped"

        if check_expiry:
            result["Expiration Date"] = get_expiration_date(domain)
        else:
            result["Expiration Date"] = "Skipped"

        results.append(result)

    return results

# Streamlit UI
def main():
    st.set_page_config(page_title="Domain Checker", layout="centered")
    st.title("🌐 Domain Status Checker")

    st.write("Select which checks to perform on each domain:")

    check_http = st.checkbox("🌍 HTTP Status Check", value=True)
    check_ns = st.checkbox("🧾 Name Server Lookup", value=True)
    check_park = st.checkbox("🚧 Parking Detection (from NS)", value=True)
    check_expiry = st.checkbox("📆 Expiration Date (WHOIS)", value=True)

    st.markdown("### ✍️ Enter domain names (one per line):")
    domain_input = st.text_area("Domains", height=200, placeholder="example.com\nmydomain.net")

    if st.button("✅ Run Checks"):
        domains = [d.strip() for d in domain_input.splitlines() if d.strip()]
        if not domains:
            st.warning("Please input at least one domain.")
            return

        with st.spinner("Checking domains..."):
            results = process_domains(domains, check_expiry, check_ns, check_park, check_http)
            df = pd.DataFrame(results)

        st.success("✅ Done!")
        st.dataframe(df)

        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button("📥 Download Results as CSV", csv, "domain_check_results.csv", "text/csv")

if __name__ == "__main__":
    main()
