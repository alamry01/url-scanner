import streamlit as st
import requests
from urllib.parse import urlparse
from functools import lru_cache
import concurrent.futures
import time

# Configuration
REQUEST_TIMEOUT = 10

# Initialize secrets
if 'GOOGLE_API_KEY' not in st.session_state:
    try:
        st.session_state.GOOGLE_API_KEY = st.secrets["api_keys"]["GOOGLE_API_KEY"]
    except:
        st.session_state.GOOGLE_API_KEY = None

# Trusted domains
TRUSTED_DOMAINS = {
    "apple.com", "google.com", "microsoft.com", 
    "amazon.com", "facebook.com", "wikipedia.org",
    "ku.edu.kw", "aasu.edu.kw"
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
    
    profile_pic = "https://i.ibb.co/TqkMj2Hp/IMG-9641.jpg"
    if profile_pic:
        st.sidebar.image(profile_pic, width=150)
    else:
        st.sidebar.warning("Profile picture URL not set")

# --- Core Functions ---
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

@st.cache_data(ttl=3600)  # Cache for 1 hour
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
        st.error(f"URLScan.io check failed: {str(e)}")
    return None

def check_local_database(url):
    """Check against local threat database"""
    domain = urlparse(url).netloc.lower()
    if domain in LOCAL_THREATS:
        return {
            'source': 'Local Database',
            'threat': LOCAL_THREATS[domain],
            'certainty': 'High'
        }
    return None

def check_google_safebrowsing(url):
    """Check using Google Safe Browsing"""
    if not st.session_state.GOOGLE_API_KEY:
        st.warning("Google Safe Browsing API key not configured")
        return None
        
    try:
        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={st.session_state.GOOGLE_API_KEY}",
            json={
                "client": {"clientId": "SecureURLScanner", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            },
            timeout=REQUEST_TIMEOUT
        )
        if response.json().get('matches'):
            return {
                'source': 'Google Safe Browsing',
                'threat': 'Known malicious site',
                'certainty': 'High'
            }
    except Exception as e:
        st.error(f"Google Safe Browsing check failed: {str(e)}")
    return None

def perform_scan(url):
    """Main scanning logic with progress tracking"""
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    if is_trusted_domain(url):
        progress_bar.progress(100)
        status_text.success("Scan complete!")
        time.sleep(0.5)
        return 'trusted', [], []

    status_text.text("Checking URLScan.io...")
    urlscan_result = check_urlscan(url)
    progress_bar.progress(30)
    
    if urlscan_result and urlscan_result.get('safe'):
        progress_bar.progress(100)
        status_text.success("Scan complete!")
        time.sleep(0.5)
        return 'safe', [urlscan_result], []

    findings = []
    service_status = []
    checks = [check_local_database, check_google_safebrowsing]
    
    status_text.text("Running security checks...")
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(check, url): check.__name__ for check in checks}
        for i, future in enumerate(concurrent.futures.as_completed(futures, timeout=REQUEST_TIMEOUT+2)):
            try:
                if result := future.result():
                    findings.append(result)
                progress_bar.progress(60 + (i+1)*15)
            except concurrent.futures.TimeoutError:
                service_status.append(f"{futures[future]} timed out")
            except Exception as e:
                service_status.append(f"{futures[future]} failed: {str(e)}")

    progress_bar.progress(100)
    status_text.success("Scan complete!")
    time.sleep(0.5)
    
    if urlscan_result and not urlscan_result.get('safe'):
        return 'unsafe', [urlscan_result] + findings, service_status
    elif findings:
        return 'suspicious', findings, service_status
    else:
        return 'unknown', [], service_status

def display_results(verdict, findings, service_status, url):
    """Display scan results with detailed information"""
    st.header("🔍 Scan Results")
    
    # Verdict display
    verdict_colors = {
        'trusted': ("✅ Trusted", "green"),
        'safe': ("✅ Safe", "green"),
        'suspicious': ("⚠️ Suspicious", "orange"),
        'unsafe': ("❌ Dangerous", "red"),
        'unknown': ("❓ Unknown", "gray")
    }
    
    text, color = verdict_colors.get(verdict, ("❓ Unknown", "gray"))
    st.markdown(f"<h3 style='color:{color}'>{text}</h3>", unsafe_allow_html=True)
    st.write(f"**URL:** `{url}`")
    
    # Findings section
    if findings:
        st.subheader("Threat Findings")
        for finding in findings:
            with st.expander(f"{finding.get('source', 'Unknown source')}"):
                cols = st.columns([1, 3])
                cols[0].metric("Certainty", finding.get('certainty', 'Unknown'))
                cols[1].write(f"**Threat:** {finding.get('threat', 'Unknown')}")
                if 'details' in finding:
                    st.markdown(f"[View detailed report ↗️]({finding['details']})")
    
    # Service status section
    if service_status:
        st.subheader("Service Status")
        for status in service_status:
            st.warning(f"⚠️ {status}")
    
    # Recommendations
    st.subheader("Recommendation")
    if verdict in ['trusted', 'safe']:
        st.success("This URL appears safe to use")
    elif verdict == 'suspicious':
        st.warning("Exercise caution when visiting this URL")
    elif verdict == 'unsafe':
        st.error("Do not visit this URL - potential security risk")
    else:
        st.info("Unable to determine safety with certainty")

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
    st.caption("Comprehensive URL security verification tool")
    
    with st.expander("ℹ️ How to use"):
        st.write("""
        1. Enter any website URL in the box below
        2. Click 'Scan URL' button
        3. View detailed security report
        
        **Features:**
        - Checks against URLScan.io database
        - Verifies with Google Safe Browsing
        - Compares with known malicious patterns
        """)
    
    url = st.text_input("Enter URL to scan:", placeholder="https://example.com")
    
    if st.button("Scan URL", type="primary"):
        if not url:
            st.warning("Please enter a URL")
        else:
            processed_url = process_url(url)
            if not processed_url:
                st.error("Invalid URL format")
            else:
                with st.spinner("Initializing scanner..."):
                    time.sleep(0.5)  # Small delay for better UX
                    verdict, findings, service_status = perform_scan(processed_url)
                
                display_results(verdict, findings, service_status, processed_url)

if __name__ == "__main__":
    main()
