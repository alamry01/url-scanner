import streamlit as st
import requests
from urllib.parse import urlparse, quote
from time import sleep
from functools import lru_cache
import concurrent.futures

# Configuration
REQUEST_TIMEOUT = 10
GOOGLE_API_KEY = "AIzaSyBQJ-_bb9zfC3S4pAehM4YrKJvU33goPBA"

# Trusted domains
TRUSTED_DOMAINS = {
    "apple.com", "google.com", "microsoft.com", 
    "amazon.com", "facebook.com", "wikipedia.org",
    "ku.edu.kw", "aasu.edu.kw"  # Added your university
}

# Known malicious patterns
LOCAL_THREATS = {
    "apple-support-center.com": "Fake Apple support scam",
    "microsoft-help-desk.com": "Fake Microsoft support",
    "wells-fargo-account-login.com": "Fake banking portal",
    "paypal-security-alert.com": "PayPal phishing site",
    "adobe-flash-update.com": "Fake Flash Player update",
    "free-software-downloads.com": "Malware distribution"
}

# --- Personal About Section ---
def show_about():
    st.sidebar.markdown("## About")
    st.sidebar.markdown("""
    **Abdulrahman Alamry**  
    🎓 Software Engineering Student  
    🏫 Abdullah Al Salem University  
    🔒 Beginner Penetration Tester  
    """)
    
    # Empty profile picture URL (replace with your image link)
    profile_pic = "https://i.ibb.co/TqkMj2Hp/IMG-9641.jpg"  # ← Add your image URL here
    if profile_pic:
        st.sidebar.image(profile_pic, width=150)
    else:
        st.sidebar.warning("Profile picture URL not set")

# --- Core Functions (Same as Before) ---
@lru_cache(maxsize=100)
def process_url(url):
    """Standardize URL format and validate"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        parsed = urlparse(url)
        if not all([parsed.scheme, parsed.netloc]):
            return None
        return url
    except:
        return None

def is_trusted_domain(url):
    """Check if domain is in our trusted list"""
    domain = urlparse(url).netloc.lower()
    return any(domain.endswith(f".{t}") or domain == t for t in TRUSTED_DOMAINS)

def check_urlscan(url):
    """Definitive safety check using URLScan.io"""
    try:
        domain = urlparse(url).netloc
        response = requests.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}",
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        data = response.json()

        if not data.get("results"):
            return {'safe': True, 'source': 'URLScan.io'}

        if any(r.get('malicious', False) for r in data.get('results', [])):
            return {
                'source': 'URLScan.io',
                'threat': 'Known malicious domain',
                'certainty': 'High',
                'details': f'https://urlscan.io/search/#{domain}'
            }
    except Exception as e:
        st.warning(f"URLScan.io check failed: {str(e)}")
    return None

def perform_scan(url):
    """Main scanning logic"""
    if is_trusted_domain(url):
        return 'trusted', [], []

    urlscan_result = check_urlscan(url)
    if urlscan_result and urlscan_result.get('safe'):
        return 'safe', [urlscan_result], []
    
    findings = []
    service_status = []
    checks = [check_local_database, check_google_safebrowsing]

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(check, url): check.__name__ for check in checks}
        for future in concurrent.futures.as_completed(futures, timeout=REQUEST_TIMEOUT+2):
            try:
                if result := future.result():
                    findings.append(result)
            except concurrent.futures.TimeoutError:
                service_status.append(f"{futures[future]} timed out")
            except Exception as e:
                service_status.append(f"{futures[future]} failed: {str(e)}")

    if urlscan_result and not urlscan_result.get('safe'):
        return 'unsafe', [urlscan_result] + findings, service_status
    elif findings:
        return 'suspicious', findings, service_status
    else:
        return 'unknown', [], service_status

# --- Main App ---
def main():
    st.set_page_config(
        page_title="SecureURL Scanner",
        page_icon="🛡️",
        layout="centered"
    )
    
    # Show about section
    show_about()
    
    st.title("🛡️ SecureURL Scanner")
    st.caption("URLScan.io-powered security verification")

    url = st.text_input("Enter URL to scan:", placeholder="https://example.com")
    
    if st.button("Scan URL", type="primary"):
        if not url:
            st.warning("Please enter a URL")
        else:
            processed_url = process_url(url)
            if not processed_url:
                st.error("Invalid URL format")
            else:
                with st.spinner(f"🔍 Scanning {processed_url}..."):
                    verdict, findings, service_status = perform_scan(processed_url)
                
                display_results(verdict, findings, service_status, processed_url)

if __name__ == "__main__":
    main()