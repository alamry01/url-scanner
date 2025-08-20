import streamlit as st
import socket 
import requests
from urllib.parse import urlparse, quote
from PIL import Image
import io
import time
import re
from datetime import datetime
import json
import urllib.parse

# ===== CONSTANTS & CONFIGURATION =====
# API Keys (In production, use st.secrets or environment variables)
GOOGLE_API_KEY = "AIzaSyBQJ-_bb9zfC3S4pAehM4YrKJvU33goPBA"
SCREENSHOTAPI_TOKEN = "HT513QF-V5NMBGN-KCFQHYD-JFZYCAP"
URLSCAN_API_KEY = "0198c72e-d073-7662-9172-56ca9e404561"
VIRUSTOTAL_API_KEY = ""  # Add your VirusTotal API key

# STC Theme Configuration
STC_PRIMARY = "#D82A20"  # STC Red
STC_SECONDARY = "#CCCCCC"  # Light Gray
STC_BACKGROUND = "#121212"  # Dark background
STC_SURFACE = "#1E1E1E"  # Card background
STC_TEXT = "#FFFFFF"  # White text
STC_SUCCESS = "#4CAF50"  # Green for safe indicators
STC_WARNING = "#FF9800"  # Orange for warnings
STC_DANGER = "#F44336"  # Red for critical alerts
STC_LOGO_URL = "https://upload.wikimedia.org/wikipedia/commons/thumb/e/e3/STC-01.svg/2560px-STC-01.svg.png"

# Security Configuration
REQUEST_TIMEOUT = 20
TRUSTED_DOMAINS = {
    "stc.com.kw", "stcpay.com.kw", "stc.com.sa",
    "ku.edu.kw", "aasu.edu.kw", "gov.kw",
    "microsoft.com", "apple.com", "google.com"
}

LOCAL_THREATS = {
    "stc-login.com": "Fake STC login portal",
    "stc-bill-pay.com": "STC payment scam",
    "stc-rewards.com": "Phishing for rewards",
    "stc-wifi.com": "Fake WiFi login",
    "stc-update.com": "Malware distribution",
    "stc-offer.com": "Fraudulent offers"
}

SCREENSHOT_SERVICES = [
    {
        "name": "ScreenshotAPI.com",
        "url": "https://screenshotapi.net/api/v1/screenshot",
        "params": {
            "url": "{url}",
            "token": SCREENSHOTAPI_TOKEN,
            "delay": "5",
            "fresh": "true",
            "full_page": "true"
        },
        "headers": {"Accept": "image/png"}
    }
]

# ===== UTILITY FUNCTIONS =====
def apply_dark_theme():
    """Apply STC dark theme to the Streamlit app with enhanced styling"""
    st.markdown(f"""
    <style>
        :root {{
            --primary-color: {STC_PRIMARY};
            --background-color: {STC_BACKGROUND};
            --secondary-background-color: {STC_SURFACE};
            --text-color: {STC_TEXT};
            --font: 'Segoe UI', Tahoma, sans-serif;
        }}
        
        .stApp {{
            background-color: {STC_BACKGROUND};
            color: {STC_TEXT};
            font-family: 'Segoe UI', Tahoma, sans-serif;
        }}
        
        .stTextInput>div>div>input {{
            color: {STC_TEXT};
            background-color: {STC_SURFACE};
            border: 1px solid {STC_SECONDARY};
            border-radius: 8px;
        }}
        
        .stButton>button {{
            background-color: {STC_PRIMARY};
            color: white;
            border: none;
            border-radius: 8px;
            font-weight: bold;
            padding: 0.5rem 1rem;
            transition: all 0.3s ease;
        }}
        
        .stButton>button:hover {{
            background-color: #b8221a;
            color: white;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }}
        
        .css-1v3fvcr {{
            color: {STC_PRIMARY} !important;
        }}
        
        .stAlert {{
            background-color: {STC_SURFACE} !important;
            border-left: 4px solid {STC_PRIMARY} !important;
            border-radius: 8px;
        }}
        
        .css-1hynsf2 {{
            background-color: {STC_SURFACE};
            border-radius: 8px;
            padding: 1rem;
        }}
        
        .css-1q8dd3e {{
            color: {STC_TEXT};
        }}
        
        .block-container {{
            padding-top: 2rem;
        }}
        
        .metric-card {{
            background-color: {STC_SURFACE};
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
            border-left: 4px solid {STC_PRIMARY};
        }}
        
        .safe-indicator {{
            border-left: 4px solid {STC_SUCCESS} !important;
        }}
        
        .warning-indicator {{
            border-left: 4px solid {STC_WARNING} !important;
        }}
        
        .danger-indicator {{
            border-left: 4px solid {STC_DANGER} !important;
        }}
        
        .header-text {{
            color: {STC_PRIMARY};
            font-weight: 700;
            margin-bottom: 1rem;
        }}
        
        .subheader-text {{
            color: {STC_SECONDARY};
            font-weight: 600;
            margin-bottom: 0.5rem;
        }}
        
        .feature-icon {{
            font-size: 1.5rem;
            margin-right: 0.5rem;
            color: {STC_PRIMARY};
        }}
        
        .risk-gauge {{
            width: 100%;
            height: 200px;
            background: conic-gradient(
                {STC_SUCCESS} 0% 20%, 
                {STC_WARNING} 20% 40%, 
                {STC_DANGER} 40% 100%
            );
            border-radius: 50%;
            position: relative;
            margin: 0 auto;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        
        .risk-gauge-inner {{
            width: 70%;
            height: 70%;
            background-color: {STC_SURFACE};
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-direction: column;
        }}
        
        .risk-score {{
            font-size: 2rem;
            font-weight: bold;
            color: {STC_TEXT};
        }}
        
        .risk-level {{
            font-size: 1rem;
            color: {STC_TEXT};
        }}
        
        .gauge-needle {{
            position: absolute;
            top: 10%;
            left: 50%;
            width: 3px;
            height: 40%;
            background-color: {STC_TEXT};
            transform-origin: bottom center;
            transform: translateX(-50%) rotate(0deg);
            transition: transform 1s ease;
        }}
    </style>
    """, unsafe_allow_html=True)

def is_valid_url(url):
    """Validate URL format"""
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def get_geolocation(ip):
    """Get IP geolocation (simplified version)"""
    if ip == "N/A" or ip == "DNS Resolution Failed":
        return "Unknown"
    
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        if data['status'] == 'success':
            return f"{data['city']}, {data['country']}" if data.get('city') else data['country']
        return "Unknown"
    except:
        return "Unknown"

def check_suspicious_keywords(url):
    """Check for suspicious keywords in URL"""
    suspicious_patterns = [
        r"login", r"signin", r"verify", r"account", r"secure", 
        r"update", r"confirm", r"banking", r"paypal", r"ebay",
        r"amazon", r"apple", r"microsoft", r"facebook", r"twitter"
    ]
    
    domain = urlparse(url).netloc.lower()
    path = urlparse(url).path.lower()
    
    # Check if legitimate brand names are used in suspicious ways
    for pattern in suspicious_patterns:
        if re.search(pattern, domain) or re.search(pattern, path):
            # Additional check to see if it's not the actual domain
            if not any(brand in domain for brand in ["apple.com", "microsoft.com", "amazon.com"]):
                return True
    
    return False

def check_url_shorteners(url):
    """Check if URL uses known URL shorteners"""
    shorteners = {
        "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", 
        "buff.ly", "adf.ly", "shorte.st", "bc.vc", "bit.do"
    }
    
    domain = urlparse(url).netloc.lower()
    return domain in shorteners

# ===== CORE FUNCTIONALITY =====
def get_screenshot(url):
    """Fetch screenshot using multiple fallback services with proper URL handling"""
    
    # Clean and validate the URL first
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        # Parse URL to ensure it's valid
        parsed = urlparse(url)
        if not parsed.netloc:
            return None
            
        # Reconstruct clean URL
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            clean_url += f"?{parsed.query}"
            
    except Exception:
        return None
    
    domain = urlparse(clean_url).netloc
    
    # Method 1: Try Thum.io (free, no API key needed) - Most reliable
    try:
        # Simple URL encoding for thum.io
        encoded_url = clean_url.replace('https://', '').replace('http://', '')
        thum_url = f"https://image.thum.io/get/width/1024/crop/768/noanimate/{encoded_url}"
        
        # Test if the service responds
        response = requests.head(thum_url, timeout=10)
        if response.status_code == 200:
            return thum_url
    except Exception as e:
        print(f"Thum.io screenshot failed: {e}")
    
    # Method 2: Try S-Shot.ru (reliable Russian service)
    try:
        sshot_url = f"https://mini.s-shot.ru/1024x768/JPEG/1024/Z100/?{clean_url}"
        
        # Test the URL with a lighter check (just try to access)
        response = requests.head(sshot_url, timeout=10)
        if response.status_code in [200, 302, 404]:  # Some services return 404 on HEAD but work on GET
            return sshot_url
    except Exception as e:
        print(f"S-Shot failed: {e}")
    
    # Method 3: Try ScreenshotAPI with proper encoding (if token is valid)
    try:
        if SCREENSHOTAPI_TOKEN and SCREENSHOTAPI_TOKEN != "HT513QF-V5NMBGN-KCFQHYD-JFZYCAP":
            params = {
                'url': clean_url,
                'token': SCREENSHOTAPI_TOKEN,
                'delay': '3',
                'fresh': 'true',
                'full_page': 'false',
                'width': '1024',
                'height': '768'
            }
            
            # Build URL manually to avoid encoding issues
            base_url = "https://screenshotapi.net/api/v1/screenshot"
            param_string = "&".join([f"{k}={requests.utils.quote(str(v), safe='')}" for k, v in params.items()])
            screenshot_url = f"{base_url}?{param_string}"
            
            # Test the URL
            response = requests.head(screenshot_url, timeout=10)
            if response.status_code == 200:
                return screenshot_url
    except Exception as e:
        print(f"ScreenshotAPI failed: {e}")
    
    # Method 4: Try PagePeeker (free service)
    try:
        pagepeeker_url = f"https://api.pagepeeker.com/v2/thumbs.php?size=l&url={domain}"
        
        response = requests.head(pagepeeker_url, timeout=10)
        if response.status_code == 200:
            return pagepeeker_url
    except Exception as e:
        print(f"PagePeeker failed: {e}")
    
    # Method 5: Try Browshot API (backup)
    try:
        # Free tier with limited requests
        browshot_url = f"https://api.browshot.com/api/v1/screenshot/create?url={requests.utils.quote(clean_url, safe='')}&instance_id=26&size=screen&cache=0&details=0"
        return browshot_url
    except Exception as e:
        print(f"Browshot failed: {e}")
    
    # Method 6: Try ScreenshotLayer (alternative)
    try:
        # Basic free service
        screenshot_layer_url = f"http://api.screenshotlayer.com/api/capture?access_key=demo&url={requests.utils.quote(clean_url, safe='')}&viewport=1024x768"
        return screenshot_layer_url
    except Exception as e:
        print(f"ScreenshotLayer failed: {e}")
    
    # If all methods fail, return None
    return None

def check_urlscan_io(url, debug_mode=False):
    """Check URLScan.io for malicious indicators - ENHANCED DEBUG VERSION"""
    debug_info = []
    
    try:
        domain = urlparse(url).netloc.lower().replace("www.", "")
        
        # Search for recent scans of this domain
        query_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10"
        headers = {'User-Agent': 'STC-Scanner/1.0'}
        
        response = requests.get(query_url, headers=headers, timeout=REQUEST_TIMEOUT)
        
        debug_info.append(f"URLScan.io API Response Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            results = data.get('results', [])
            
            debug_info.append(f"Found {len(results)} URLScan.io results for {domain}")
            
            if results:
                # Analyze the results for actual threats
                malicious_count = 0
                suspicious_count = 0
                phishing_count = 0
                total_scans = len(results)
                latest_scan = results[0]  # Most recent scan
                
                for i, result in enumerate(results):
                    scan_debug = []
                    scan_debug.append(f"Analyzing scan {i+1}/{total_scans}")
                    
                    # Method 1: Check verdicts (newer API format)
                    verdicts = result.get('verdicts', {})
                    if verdicts:
                        overall = verdicts.get('overall', {})
                        if overall.get('malicious', False):
                            malicious_count += 1
                            scan_debug.append(f"  ❌ Found malicious verdict in scan {i+1}")
                        elif overall.get('suspicious', False):
                            suspicious_count += 1
                            scan_debug.append(f"  ⚠️ Found suspicious verdict in scan {i+1}")
                        else:
                            scan_debug.append(f"  ✅ No malicious/suspicious verdict in scan {i+1}")
                    else:
                        scan_debug.append(f"  ℹ️ No verdicts data in scan {i+1}")
                    
                    # Method 2: Check task data (older format)
                    task = result.get('task', {})
                    if task:
                        if task.get('malicious', False):
                            malicious_count += 1
                            scan_debug.append(f"  ❌ Found malicious task in scan {i+1}")
                        elif 'phishing' in str(task).lower():
                            phishing_count += 1
                            scan_debug.append(f"  🎣 Found phishing indicator in scan {i+1}")
                        else:
                            scan_debug.append(f"  ✅ Task data clean in scan {i+1}")
                    else:
                        scan_debug.append(f"  ℹ️ No task data in scan {i+1}")
                    
                    # Method 3: Check stats for engines that flagged it
                    stats = result.get('stats', {})
                    if stats:
                        malicious_engines = stats.get('malicious', 0)
                        suspicious_engines = stats.get('suspicious', 0)
                        
                        if malicious_engines > 0:
                            malicious_count += 1
                            scan_debug.append(f"  ❌ {malicious_engines} engines flagged scan {i+1} as malicious")
                        elif suspicious_engines > 2:  # More than 2 engines suspicious
                            suspicious_count += 1
                            scan_debug.append(f"  ⚠️ {suspicious_engines} engines flagged scan {i+1} as suspicious")
                        else:
                            scan_debug.append(f"  ✅ Stats clean: {malicious_engines} malicious, {suspicious_engines} suspicious")
                    else:
                        scan_debug.append(f"  ℹ️ No stats data in scan {i+1}")
                    
                    # Method 4: Check for specific threat categories
                    page = result.get('page', {})
                    if page:
                        page_domain = page.get('domain', '').lower()
                        # Check for suspicious domain characteristics
                        if any(indicator in page_domain for indicator in ['temp', 'tmp', 'test', 'fake']):
                            suspicious_count += 1
                            scan_debug.append(f"  ⚠️ Suspicious domain pattern in scan {i+1}: {page_domain}")
                        else:
                            scan_debug.append(f"  ✅ Domain pattern looks normal: {page_domain}")
                    
                    debug_info.extend(scan_debug)
                
                # Get public URL for the latest scan
                scan_id = latest_scan.get('uuid') or latest_scan.get('_id')
                public_url = f"https://urlscan.io/result/{scan_id}/" if scan_id else None
                
                # Combine all threat indicators
                total_threats = malicious_count + phishing_count
                
                summary = [
                    "URLScan.io Analysis Summary:",
                    f"  📊 Total scans: {total_scans}",
                    f"  ❌ Malicious: {malicious_count}",
                    f"  ⚠️ Suspicious: {suspicious_count}",
                    f"  🎣 Phishing: {phishing_count}",
                    f"  🔗 Public URL: {public_url or 'Not available'}"
                ]
                debug_info.extend(summary)
                
                # Only report as threat if there are actual malicious indicators
                if total_threats > 0:
                    return {
                        'source': 'URLScan.io',
                        'threat': f"Malicious/Phishing activity detected in {total_threats}/{total_scans} recent scans",
                        'certainty': 'High' if total_threats > 1 else 'Medium',
                        'severity': 'High' if total_threats > 2 else 'Medium'
                    }, public_url, debug_info
                elif suspicious_count > 1:  # Only report if multiple suspicious indicators
                    return {
                        'source': 'URLScan.io',
                        'threat': f"Suspicious activity detected in {suspicious_count}/{total_scans} recent scans",
                        'certainty': 'Medium',
                        'severity': 'Medium'
                    }, public_url, debug_info
                else:
                    # Domain has been scanned but no significant threats found
                    debug_info.append("✅ No significant threats found in URLScan.io")
                    return None, public_url, debug_info
        else:
            debug_info.append(f"❌ URLScan.io API error: {response.status_code} - {response.text}")

        return None, None, debug_info

    except Exception as e:
        debug_info.append(f"❌ URLScan.io check failed: {e}")
        return None, None, debug_info

def check_local_database(url):
    """Check against known phishing domains"""
    domain = urlparse(url).netloc.lower()
    for threat_domain, description in LOCAL_THREATS.items():
        if threat_domain in domain:
            return {
                'source': 'STC Threat Database',
                'threat': description,
                'certainty': 'High',
                'severity': 'High'
            }
    return None

def check_google_safebrowsing(url):
    """Check URL against Google's Safe Browsing database"""
    try:
        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}",
            json={
                "client": {"clientId": "STCScanner", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            },
            timeout=REQUEST_TIMEOUT
        )
        data = response.json()
        if data.get('matches'):
            threats = [match['threatType'] for match in data['matches']]
            return {
                'source': 'Google Safe Browsing',
                'threat': f"Known malicious URL: {', '.join(threats)}",
                'certainty': 'High',
                'severity': 'Critical'
            }
    except Exception as e:
        st.warning(f"Safe Browsing check failed: {str(e)}")
    return None

def check_virustotal(url):
    """Check URL against VirusTotal (if API key is provided)"""
    if not VIRUSTOTAL_API_KEY:
        return None
        
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        # First, submit URL for analysis
        submit_response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=REQUEST_TIMEOUT
        )
        
        if submit_response.status_code == 200:
            analysis_id = submit_response.json()['data']['id']
            # Wait a moment and get the results
            time.sleep(2)
            result_response = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=REQUEST_TIMEOUT
            )
            
            if result_response.status_code == 200:
                stats = result_response.json()['data']['attributes']['stats']
                if stats['malicious'] > 0:
                    return {
                        'source': 'VirusTotal',
                        'threat': f"Detected by {stats['malicious']} security vendors",
                        'certainty': 'High',
                        'severity': 'Critical' if stats['malicious'] > 5 else 'High'
                    }
    except Exception as e:
        # Fail silently as this is an optional feature
        pass
        
    return None

def calculate_risk_score(findings, website_info):
    """Calculate a risk score based on findings and website info"""
    score = 0
    factors = []
    
    # Base score adjustments based on findings
    for finding in findings:
        if finding['severity'] == 'Critical':
            score += 40
            factors.append(f"{finding['source']}: Critical threat")
        elif finding['severity'] == 'High':
            score += 25
            factors.append(f"{finding['source']}: High threat")
        elif finding['severity'] == 'Medium':
            score += 15
            factors.append(f"{finding['source']}: Medium threat")
    
    # SSL issues
    if "SSL Error" in website_info.get('ssl', '') or "Not Secure" in website_info.get('ssl', ''):
        score += 15
        factors.append("SSL issues detected")
    
    # Suspicious keywords
    if website_info.get('suspicious_keywords') == 'Yes':
        score += 10
        factors.append("Suspicious keywords in URL")
    
    # URL shortener
    if website_info.get('url_shortener') == 'Yes':
        score += 15
        factors.append("URL shortener detected")
    
    # Ensure score is between 0 and 100
    score = min(100, score)
    
    # Determine risk level
    if score >= 70:
        risk_level = "High Risk"
    elif score >= 40:
        risk_level = "Medium Risk"
    elif score >= 20:
        risk_level = "Low Risk"
    else:
        risk_level = "Very Low Risk"
    
    return score, risk_level, factors

def create_risk_gauge(score):
    """Create a risk gauge visualization using CSS"""
    # Calculate needle rotation (0deg at 0, 180deg at 100)
    rotation = (score / 100) * 180
    
    gauge_html = f"""
    <div class="risk-gauge">
        <div class="gauge-needle" style="transform: translateX(-50%) rotate({rotation}deg);"></div>
        <div class="risk-gauge-inner">
            <div class="risk-score">{score}</div>
            <div class="risk-level">Risk Score</div>
        </div>
    </div>
    <div style="text-align: center; margin-top: 10px; color: {STC_TEXT};">
        <span style="color: {STC_SUCCESS};">0-20: Safe</span> | 
        <span style="color: {STC_WARNING};">20-40: Low Risk</span> | 
        <span style="color: {STC_DANGER};">40-100: High Risk</span>
    </div>
    """
    return gauge_html

def get_website_info(url):
    """Collect basic website info: IP, SSL, server, suspicious keywords, URL shortener, etc."""
    info = {}
    domain = urlparse(url).netloc

    # DNS / IP lookup
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        ip = "DNS Resolution Failed"

    # Geolocation
    geo = get_geolocation(ip)

    # SSL check (simplified)
    ssl_status = "🔒 Secure" if url.startswith("https://") else "Not Secure"

    # Suspicious keywords
    suspicious = "Yes" if check_suspicious_keywords(url) else "No"

    # URL shortener
    shortener = "Yes" if check_url_shorteners(url) else "No"

    # Fill info dictionary
    info['domain'] = domain
    info['ip'] = ip
    info['server'] = "Unknown"  # Could be enhanced by fetching headers
    info['ssl'] = ssl_status
    info['load_time'] = "N/A"
    info['status'] = "200"  # Could be enhanced by sending HEAD request
    info['redirects'] = "No"  # Could check if final_url != original_url
    info['domain_age'] = "N/A"
    info['geolocation'] = geo
    info['suspicious_keywords'] = suspicious
    info['url_shortener'] = shortener

    return info

def perform_scan(url, debug_mode=False):
    """Orchestrate all security checks"""
    domain = urlparse(url).netloc
    debug_info = []
    
    # Check trusted domains first
    if any(domain.endswith(f".{t}") or domain == t for t in TRUSTED_DOMAINS):
        website_info = {
            "domain": domain,
            "ip": "N/A",
            "server": "Trusted Domain",
            "ssl": "🔒 Secure",
            "load_time": "N/A",
            "status": "200",
            "redirects": "No",
            "domain_age": "N/A (Trusted)",
            "geolocation": "N/A (Trusted)",
            "suspicious_keywords": "No",
            "url_shortener": "No"
        }
        return 'trusted', [], None, website_info, 0, "Very Low Risk", [], None, []
    
    # Non-trusted domains
    final_url = url if url.startswith(('http://','https://')) else 'https://' + url
    screenshot_url = get_screenshot(final_url)
    website_info = get_website_info(final_url)
    findings = []
    urlscan_url = None
    
    # Security checks
    if result := check_local_database(final_url):
        findings.append(result)
    if result := check_google_safebrowsing(final_url):
        findings.append(result)
    if result := check_virustotal(final_url):
        findings.append(result)
    
    # URLScan.io results - FIXED: Only adds to findings if actual threats found
    urlscan_result, urlscan_public_url, urlscan_debug = check_urlscan_io(final_url, debug_mode)
    if urlscan_result:
        findings.append(urlscan_result)
    if urlscan_public_url:
        urlscan_url = urlscan_public_url
    if debug_mode:
        debug_info.extend(urlscan_debug)
    
    # Risk score
    risk_score, risk_level, risk_factors = calculate_risk_score(findings, website_info)
    
    return ('unsafe' if findings else 'safe', findings, screenshot_url, website_info, risk_score, risk_level, risk_factors, urlscan_url, debug_info)

# ===== STREAMLIT UI =====
def main():
    """Main application interface"""
    st.set_page_config(
        page_title="STC Secure Scanner",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="collapsed"
    )
    apply_dark_theme()
    
    # Header Section
    col1, col2, col3 = st.columns([1, 6, 1])
    with col1:
        try:
            st.image(STC_LOGO_URL, width=100)
        except:
            # Fallback if logo fails to load
            st.markdown(f"""
            <div style="
                width: 80px; 
                height: 80px; 
                background-color: {STC_PRIMARY}; 
                border-radius: 8px;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-weight: bold;
                font-size: 24px;
                margin: 10px 0;
            ">STC</div>
            """, unsafe_allow_html=True)
    with col2:
        st.markdown("""
        <div style="display: flex; flex-direction: column; justify-content: center; height: 100px;">
            <h1 class='header-text' style="margin: 0; line-height: 1.2;">STC Secure Web Scanner</h1>
            <p style="margin: 5px 0 0 0; color: #CCCCCC;">Advanced cybersecurity scanning for STC customers</p>
        </div>
        """, unsafe_allow_html=True)
    with col3:
        st.write("")  # Empty column for spacing
    
    st.markdown("---")
    
    # Main content area
    col1, col2 = st.columns([3, 1])
    
    with col1:
        # Scanner Input
        url = st.text_input("Enter website URL to scan:", placeholder="https://example.com", key="url_input")
        
        # Add debug toggle
        debug_mode = st.checkbox("Enable Debug Mode (shows detailed URLScan.io analysis)", value=False)
        
        scan_button = st.button("🔍 Scan Website", type="primary", use_container_width=True)
        
        if scan_button and url:
            if not is_valid_url(url):
                st.error("Please enter a valid URL (e.g., https://example.com)")
            else:
                processed_url = f"https://{url}" if not url.startswith(('http://', 'https://')) else url
                
                with st.spinner("Scanning website... This may take up to 30 seconds"):
                    verdict, findings, screenshot, website_info, risk_score, risk_level, risk_factors, urlscan_url, debug_info = perform_scan(processed_url, debug_mode)
                
                # Debug Information
                if debug_mode and debug_info:
                    with st.expander("🔍 URLScan.io Debug Information", expanded=True):
                        for info in debug_info:
                            st.text(info)
                
                # Display Results
                st.subheader("Scan Results")
                
                # Risk Score Gauge
                gauge_col, verdict_col = st.columns([1, 2])
                with gauge_col:
                    st.markdown(create_risk_gauge(risk_score), unsafe_allow_html=True)
                
                with verdict_col:
                    if verdict == 'trusted':
                        st.success("✅ Trusted STC Website")
                    elif verdict == 'safe':
                        st.success("✅ No Threats Detected")
                    elif verdict == 'unsafe':
                        st.error(f"⛔ {risk_level}")
                    
                    st.write(f"**Risk Factors:** {', '.join(risk_factors) if risk_factors else 'None detected'}")
                    
                    # Add URLScan.io button if available (even for safe sites)
                    if urlscan_url:
                        st.markdown(f"""
                        <a href="{urlscan_url}" target="_blank">
                            <button style="
                                background-color: {STC_PRIMARY};
                                color: white;
                                border: none;
                                padding: 10px 20px;
                                border-radius: 5px;
                                cursor: pointer;
                                margin-top: 10px;
                            ">🔍 View Detailed Analysis on URLScan.io</button>
                        </a>
                        """, unsafe_allow_html=True)
                
                # Threat Findings
                if findings:
                    st.subheader("Threat Detections")
                    for finding in findings:
                        with st.container():
                            if finding['severity'] == 'Critical':
                                st.error(f"**{finding['source']}**: {finding['threat']}")
                            elif finding['severity'] == 'High':
                                st.warning(f"**{finding['source']}**: {finding['threat']}")
                            else:
                                st.info(f"**{finding['source']}**: {finding['threat']}")
                
                # Screenshot section
                st.subheader("Website Preview")
                
                screenshot_success = False
                
                if screenshot:
                    try:
                        # Try to display the screenshot with error handling
                        col1, col2 = st.columns([3, 1])
                        with col1:
                            st.image(screenshot, caption="Website Screenshot", use_column_width=True)
                            screenshot_success = True
                        with col2:
                            st.markdown(f"""
                            <div style="background-color: #1E1E1E; padding: 10px; border-radius: 5px;">
                                <small>Screenshot Service:</small><br>
                                <a href="{screenshot}" target="_blank" style="color: {STC_PRIMARY}; font-size: 0.8em;">Open Image</a>
                            </div>
                            """, unsafe_allow_html=True)
                    except Exception as e:
                        st.warning("Screenshot failed to load")
                        screenshot_success = False
                
                # If screenshot fails, provide alternatives
                if not screenshot_success:
                    st.markdown("### Alternative Preview Methods:")
                    
                    # Create tabs for different preview methods
                    tab1, tab2, tab3 = st.tabs(["📸 Simple Screenshot", "🖥️ Live Preview", "🔗 Direct Access"])
                    
                    with tab1:
                        # Try multiple simple screenshot services
                        screenshot_services = [
                            {
                                "name": "Thum.io", 
                                "url": f"https://image.thum.io/get/width/800/crop/600/{processed_url.replace('https://', '').replace('http://', '')}"
                            },
                            {
                                "name": "S-Shot.ru",
                                "url": f"https://mini.s-shot.ru/1024x768/JPEG/800/Z100/?{processed_url}"
                            },
                            {
                                "name": "PagePeeker",
                                "url": f"https://api.pagepeeker.com/v2/thumbs.php?size=l&url={urlparse(processed_url).netloc}"
                            },
                            {
                                "name": "ScreenshotLayer",
                                "url": f"http://api.screenshotlayer.com/api/capture?access_key=demo&url={requests.utils.quote(processed_url, safe='')}&viewport=1024x768"
                            }
                        ]
                        
                        screenshot_loaded = False
                        for service in screenshot_services:
                            try:
                                col1, col2 = st.columns([2, 1])
                                with col1:
                                    st.image(service["url"], caption=f"{service['name']} Preview", use_column_width=True)
                                    screenshot_loaded = True
                                with col2:
                                    st.markdown(f"**{service['name']}**")
                                    st.markdown(f"[Open Full Size]({service['url']})")
                                break  # If one works, don't try others
                            except Exception as e:
                                st.write(f"❌ {service['name']}: Failed to load")
                                continue
                        
                        if not screenshot_loaded:
                            st.error("All screenshot services failed. This could be due to:")
                            st.markdown("""
                            - The website blocks screenshots
                            - Network connectivity issues
                            - Screenshot services are temporarily down
                            - The website requires authentication
                            """)
                            
                            # Provide manual screenshot instructions
                            st.info("""
                            **Manual Screenshot Options:**
                            1. Visit the website directly and take your own screenshot
                            2. Use browser extensions like "Full Page Screen Capture"
                            3. Try online tools like web.archive.org to see cached versions
                            """)
                            
                        # Add a refresh button for screenshots
                        if st.button("🔄 Try Screenshot Services Again", key="retry_screenshot"):
                            st.experimental_rerun()
                    
                    with tab2:
                        # Embedded iframe (use with caution - some sites block iframes)
                        st.markdown("**Live Website Preview:**")
                        st.markdown(f"""
                        <div style="border: 2px solid {STC_PRIMARY}; border-radius: 8px; overflow: hidden;">
                            <iframe src="{processed_url}" width="100%" height="600" frameborder="0" 
                                    style="border: none;" 
                                    sandbox="allow-scripts allow-same-origin allow-forms allow-popups">
                                <p>Your browser doesn't support iframes. <a href="{processed_url}">Click here to visit the site</a></p>
                            </iframe>
                        </div>
                        """, unsafe_allow_html=True)
                        st.caption("⚠️ This is a live preview. Exercise caution when interacting with suspicious websites.")
                    
                    with tab3:
                        # Direct access with safety warnings
                        domain = urlparse(processed_url).netloc
                        
                        if verdict == 'unsafe':
                            st.error("🚨 **WARNING**: This website has been flagged as potentially dangerous!")
                            st.markdown("**Detected Threats:**")
                            for finding in findings:
                                st.markdown(f"- {finding['source']}: {finding['threat']}")
                            st.markdown("**⚠️ Proceed with extreme caution or avoid visiting this site.**")
                        
                        st.markdown(f"""
                        <div style="background-color: #1E1E1E; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
                            <p style="margin-bottom: 15px; font-size: 1.1em;">Manual Website Access:</p>
                            <div style="margin-bottom: 15px;">
                                <strong>Domain:</strong> {domain}<br>
                                <strong>Full URL:</strong> {processed_url}
                            </div>
                            <a href="{processed_url}" target="_blank" style="
                                background-color: {STC_PRIMARY if verdict != 'unsafe' else STC_DANGER};
                                color: white;
                                padding: 12px 24px;
                                border-radius: 6px;
                                text-decoration: none;
                                display: inline-block;
                                font-weight: bold;
                                margin: 5px;
                            ">🔗 {'Visit Website' if verdict != 'unsafe' else 'Visit (Risky)'}</a>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        # Additional tools - FIXED: Moved URL encoding outside f-string
                        st.markdown("**Additional Analysis Tools:**")
                        col1, col2, col3 = st.columns(3)
                        
                        # Fix the f-string issue by doing URL encoding outside the f-string
                        encoded_url = requests.utils.quote(processed_url, safe="")
                        virustotal_url = f"https://www.virustotal.com/gui/url/{encoded_url}"
                        
                        with col1:
                            st.markdown(f"[VirusTotal]({virustotal_url})")
                        with col2:
                            st.markdown(f"[URLVoid](https://www.urlvoid.com/scan/{domain})")
                        with col3:
                            if urlscan_url:
                                st.markdown(f"[URLScan.io]({urlscan_url})")
                            else:
                                st.markdown(f"[URLScan.io](https://urlscan.io/search/#{domain})")
                
                # Technical Details
                st.subheader("Technical Analysis")
                
                # Create two columns for technical details
                tech_col1, tech_col2 = st.columns(2)
                
                with tech_col1:
                    st.markdown(f"<div class='metric-card { 'safe-indicator' if website_info.get('ssl', '').startswith('🔒') else 'danger-indicator' }'>", unsafe_allow_html=True)
                    st.metric("SSL Security", website_info.get("ssl", "N/A"))
                    st.markdown("</div>", unsafe_allow_html=True)
                    
                    st.markdown(f"<div class='metric-card'>", unsafe_allow_html=True)
                    st.metric("Domain Age", website_info.get("domain_age", "N/A"))
                    st.markdown("</div>", unsafe_allow_html=True)
                    
                    st.markdown(f"<div class='metric-card { 'warning-indicator' if website_info.get('suspicious_keywords') == 'Yes' else '' }'>", unsafe_allow_html=True)
                    st.metric("Suspicious Keywords", website_info.get("suspicious_keywords", "N/A"))
                    st.markdown("</div>", unsafe_allow_html=True)
                    
                    st.markdown(f"<div class='metric-card'>", unsafe_allow_html=True)
                    st.metric("Load Time", website_info.get("load_time", "N/A"))
                    st.markdown("</div>", unsafe_allow_html=True)
                
                with tech_col2:
                    st.markdown(f"<div class='metric-card'>", unsafe_allow_html=True)
                    st.metric("Server", website_info.get("server", "N/A"))
                    st.markdown("</div>", unsafe_allow_html=True)
                    
                    st.markdown(f"<div class='metric-card { 'warning-indicator' if website_info.get('url_shortener') == 'Yes' else '' }'>", unsafe_allow_html=True)
                    st.metric("URL Shortener", website_info.get("url_shortener", "N/A"))
                    st.markdown("</div>", unsafe_allow_html=True)
                    
                    st.markdown(f"<div class='metric-card'>", unsafe_allow_html=True)
                    st.metric("Geolocation", website_info.get("geolocation", "N/A"))
                    st.markdown("</div>", unsafe_allow_html=True)
                    
                    st.markdown(f"<div class='metric-card'>", unsafe_allow_html=True)
                    st.metric("Response Status", website_info.get("status", "N/A"))
                    st.markdown("</div>", unsafe_allow_html=True)
                
                # Additional details in expander
                with st.expander("View Raw Technical Data"):
                    st.json(website_info)
    
    with col2:
        # Sidebar with features and information
        st.markdown("### 🔒 Security Features")
        st.markdown("""
        <div style="background-color: #1E1E1E; padding: 15px; border-radius: 8px; margin-bottom: 15px;">
            <p style="margin: 5px 0;"><span class="feature-icon">📸</span> Live Screenshot</p>
            <p style="margin: 5px 0;"><span class="feature-icon">🌐</span> Domain Analysis</p>
            <p style="margin: 5px 0;"><span class="feature-icon">🛡️</span> Threat Detection</p>
            <p style="margin: 5px 0;"><span class="feature-icon">🔍</span> SSL Verification</p>
            <p style="margin: 5px 0;"><span class="feature-icon">📊</span> Risk Assessment</p>
            <p style="margin: 5px 0;"><span class="feature-icon">📍</span> Geolocation</p>
            <p style="margin: 5px 0;"><span class="feature-icon">🔗</span> URLScan.io Integration</p>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("### 📈 Recent Scans")
        # Placeholder for recent scans - in a real app, you'd store this in session state or a database
        st.info("Scan history will appear here after multiple scans")
        
        st.markdown("### 📝 Tips for Safe Browsing")
        st.markdown("""
        - Always check the URL before entering credentials
        - Look for the 🔒 symbol in your browser
        - Don't click on suspicious links in emails
        - Keep your browser and security software updated
        - Use STC's secure browsing tools
        """)
    
    # Footer
    st.markdown("---")
    st.markdown(
        """<div style="text-align: center; color: #666; font-size: 0.8em;">
        STC Kuwait - Cybersecurity Division © 2023 | Report phishing: security@stc.com.kw
        </div>""",
        unsafe_allow_html=True
    )

if __name__ == "__main__":
    main()
