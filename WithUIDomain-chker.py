import os
import requests
import pandas as pd
import dns.resolver  # pip install dnspython
import whois
from datetime import datetime

# List of known parking name servers (add more as needed)
PARKING_KEYWORDS = [
    "parkingcrew", "sedoparking", "bodis", "afternic", "above", "uniregistry",
    "domaincontrol", "cashparking", "namebright", "namestore"
]

def get_expiration_date(domain):
    try:
        w = whois.whois(domain)
        exp_date = w.expiration_date
        if isinstance(exp_date, list):  # Some domains return a list of dates
            exp_date = exp_date[0]
        if isinstance(exp_date, datetime):
            return exp_date.strftime("%Y-%m-%d")
        return "Unknown"
    except Exception:
        return "Lookup Failed"
    
    
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

def get_name_servers(domain):
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        ns_records = sorted([str(rdata.target).strip(".") for rdata in answers])
        return ns_records
    except Exception:
        return []

def is_parking_ns(ns_records):
    for ns in ns_records:
        for keyword in PARKING_KEYWORDS:
            if keyword in ns.lower():
                return True
    return False

def load_domains(file_path):
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_file = os.path.join(script_dir, "websites.txt")
    output_file = os.path.join(script_dir, "domain_status.csv")

    domains = load_domains(input_file)
    results = []

    print("Checking websites and name servers...\n")

    for domain in domains:
        status = check_website(domain)
        ns_records = get_name_servers(domain)
        parked = "Yes" if is_parking_ns(ns_records) else "No"
        print(f"{domain}: {status} | Parked: {parked}")

        results.append({
            "Domain": domain,
            "Status": status,
            "Name Servers": ", ".join(ns_records) if ns_records else "N/A",
            "Possibly Parked": parked
        })
    

    # Sort: Inaccessible and Possibly Parked on top
    results.sort(key=lambda x: (x["Status"] != "Inaccessible", x["Possibly Parked"] != "Yes"))

    df = pd.DataFrame(results)
    df.to_csv(output_file, index=False)

    print(f"\nResults saved to {output_file}")

if __name__ == "__main__":
    main()

    
