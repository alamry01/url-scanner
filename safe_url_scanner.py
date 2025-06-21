import streamlit as st
import requests
from urllib.parse import urlparse, quote
from PIL import Image
import io
import time
import os
from datetime import datetime
import concurrent.futures
from functools import lru_cache

# Configuration
REQUEST_TIMEOUT = 20
GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY', 'AIzaSyBQJ-_bb9zfC3S4pAehM4YrKJvU33goPBA')
URLSCAN_API_KEY = os.getenv('URLSCAN_API_KEY', '')  # Register at urlscan.io for free API key

# Trusted domains and threats (unchanged from your original)
TRUSTED_DOMAINS = {
    "apple.com", "google.com", "microsoft.com", 
    "amazon.com", "facebook.com", "wikipedia.org",
    "ku.edu.kw", "aasu.edu.kw"
}

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
    st.sidebar.image("https://i.ibb.co/TqkMj2Hp/IMG-9641.jpg", width=150)

# --- URL Processing ---
@lru_cache(maxsize=100)
def process_url(url):
    """Standardize and validate URL"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        parsed = urlparse(url)
        if not all([parsed.scheme, parsed.netloc]):
            return None
        return url
    except:
        return None

# --- Reliable Screenshot Capture ---
def get_website_screenshot(url):
    """Get screenshot with multiple fallback services"""
    services = [
        {"url": "https://render-tron.appspot.com/screenshot/{url}?width=800&height=600", "timeout": 15},
        {"url": "https://s0.wp.com/mshots/v1/{url}?w=800&h=600", "timeout": 10},
        {"url": "https://api.pagepeeker.com/v2/thumbs.php?size=l&url={url}", "timeout": 10}
    ]
    
    for service in services:
        try:
            response = requests.get(
                service["url"].format(url=quote(url)),
                stream=True,
                timeout=service["timeout"],
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            response.raise_for_status()
            img = Image.open(io.BytesIO(response.content))
            if img.size[0] > 10:  # Validate image
                return img
        except:
            continue
    
    return None

# --- Security Checks (Original + Enhanced) ---
def check_local_database(url):
    """Original local threat check"""
    domain = urlparse(url).netloc.lower()
    for threat_domain, description in LOCAL_THREATS.items():
        if threat_domain in domain:
            return {
                'source': 'Local Database',
                'threat': description,
                'certainty': 'High',
                'details': f'Known malicious pattern: {threat_domain}'
            }
    return None

def check_google_safebrowsing(url):
    """Original Google Safe Browsing check"""
    try:
        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}",
            json={
                "client": {"clientId": "SecureURLScanner", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            },
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        if response.json().get('matches'):
            return {
                'source': 'Google Safe Browsing',
                'threat': 'Known malicious URL',
                'certainty': 'High',
                'details': 'https://transparencyreport.google.com/safe-browsing/search'
            }
    except Exception as e:
        st.warning(f"Google Safe Browsing check failed: {str(e)}")
    return None

def check_urlscan(url):
    """Enhanced URLScan.io integration"""
    try:
        # Quick domain search
        domain = urlparse(url).netloc
        search_response = requests.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}",
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=REQUEST_TIMEOUT
        )
        search_response.raise_for_status()
        search_data = search_response.json()

        if not search_data.get("results"):
            return {'safe': True, 'source': 'URLScan.io'}

        if any(r.get('malicious', False) for r in search_data.get('results', [])):
            return {
                'source': 'URLScan.io',
                'threat': 'Known malicious domain',
                'certainty': 'High',
                'details': f'https://urlscan.io/search/#{domain}'
            }

        # Full scan if API key available
        if URLSCAN_API_KEY:
            submit_response = requests.post(
                "https://urlscan.io/api/v1/scan/",
                headers={"Content-Type": "application/json", "API-Key": URLSCAN_API_KEY},
                json={"url": url, "public": "on"},
                timeout=REQUEST_TIMEOUT
            )
            submit_response.raise_for_status()
            scan_id = submit_response.json().get('uuid')
            return {
                'source': 'URLScan.io',
                'threat': 'Submitted for analysis',
                'certainty': 'Pending',
                'details': f'https://urlscan.io/result/{scan_id}/'
            }
        return None
    except Exception as e:
        st.warning(f"URLScan.io check failed: {str(e)}")
        return None

# --- Scanning Logic ---
def perform_scan(url):
    """Perform all security checks and capture screenshot"""
    if is_trusted_domain(url):
        return 'trusted', [], [], None, None

    screenshot = None
    screenshot_error = None
    
    # Get screenshot in parallel with security checks
    with concurrent.futures.ThreadPoolExecutor() as executor:
        screenshot_future = executor.submit(get_website_screenshot, url)
        
        urlscan_result = check_urlscan(url)
        if urlscan_result and urlscan_result.get('safe'):
            screenshot = screenshot_future.result()
            return 'safe', [urlscan_result], [], screenshot, None

        findings = []
        service_status = []
        checks = [check_local_database, check_google_safebrowsing]

        for check in checks:
            try:
                if result := check(url):
                    findings.append(result)
            except Exception as e:
                service_status.append(f"{check.__name__} failed: {str(e)}")

        screenshot = screenshot_future.result()
        if not screenshot:
            screenshot_error = "All screenshot services failed"

        if urlscan_result and not urlscan_result.get('safe'):
            return 'unsafe', [urlscan_result] + findings, service_status, screenshot, screenshot_error
        elif findings:
            return 'suspicious', findings, service_status, screenshot, screenshot_error
        else:
            return 'unknown', [], service_status, screenshot, screenshot_error

# --- Display Results ---
def display_results(verdict, findings, service_status, url, screenshot, screenshot_error):
    """Show results with screenshot"""
    st.subheader(f"Scan Results for: {url}")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        verdicts = {
            'trusted': ('🟢', 'Trusted Domain'),
            'safe': ('🟢', 'No Threats Found'),
            'suspicious': ('🟡', 'Potential Risk'),
            'unsafe': ('🔴', 'Malicious Detected'),
            'unknown': ('⚪', 'Inconclusive Results')
        }
        emoji, status = verdicts.get(verdict, ('❓', 'Unknown'))
        st.markdown(f"### {emoji} {status}")
        
        if findings:
            with st.expander("🔍 Detailed Findings", expanded=True):
                for finding in findings:
                    st.write(f"**Source:** {finding.get('source')}")
                    st.write(f"**Threat:** {finding.get('threat')}")
                    st.write(f"**Certainty:** {finding.get('certainty')}")
                    if 'details' in finding:
                        st.markdown(f"[More info]({finding['details']})")
                    st.divider()
        
        if service_status:
            st.warning("Service Issues:")
            for status in service_status:
                st.code(status)
    
    with col2:
        if screenshot:
            st.image(screenshot, caption="Website Preview", use_column_width=True)
        elif screenshot_error:
            st.error(screenshot_error)
        else:
            st.info("Screenshot not available")

# --- Main App ---
def main():
    st.set_page_config(
        page_title="SecureURL Scanner", 
        page_icon="🛡️", 
        layout="centered"
    )
    show_about()
    st.title("🛡️ SecureURL Scanner")
    st.caption("Comprehensive URL analysis with screenshot verification")
    
    url = st.text_input("Enter URL to scan:", placeholder="https://example.com")
    
    if st.button("Scan URL", type="primary"):
        if not url:
            st.warning("Please enter a URL")
        else:
            processed_url = process_url(url)
            if not processed_url:
                st.error("Invalid URL format")
            else:
                with st.spinner("🔍 Analyzing URL..."):
                    verdict, findings, service_status, screenshot, screenshot_error = perform_scan(processed_url)
                display_results(verdict, findings, service_status, processed_url, screenshot, screenshot_error)

if __name__ == "__main__":
    main()
