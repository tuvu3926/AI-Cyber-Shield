import re
import socket
import requests
import contextlib
import io
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import pandas as pd
import warnings
warnings.filterwarnings("ignore")
class URLFeatureExtractor:
    def __init__(self, top_domains_file="top_10000_domains.csv"):
        self.shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                                   r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                                   r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                                   r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.ny|lnkd\.in|db\.tt|" \
                                   r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                                   r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                                   r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net"
        
        self.THRESHOLDS = {
            'request_url': (22, 61),
            'url_of_anchor': (31, 67),
            'links_in_tags': (17, 81),
            'redirect': (1, 3),
        }
        self.top_domains = self._load_top_domains(top_domains_file)
    def _load_top_domains(self, file_path):
        domains = set()
        try:
            with open(file_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    if "," in line:
                        domain = line.split(",")[-1]
                    else:
                        domain = line
                    domain = domain.lower()
                    if domain.startswith("www."):
                        domain = domain[4:]
                    domains.add(domain)
        except FileNotFoundError:
            pass # File not found, ignore
        return domains
    def get_base_domain(self, url):
        netloc = urlparse(url).netloc.lower()
        return netloc.replace("www.", "")
    def _safe_whois(self, domain):
        try:
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                w = whois.whois(domain)
            return w
        except:
            return None
    def extract_features(self, url, timeout=5):
        features = []
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname if parsed_url.hostname else ""
        # 1. having_IP_Address
        ip_pattern = r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|' \
                     r'0x[0-9a-fA-F]+\.0x[0-9a-fA-F]+\.0x[0-9a-fA-F]+\.0x[0-9a-fA-F]+'
        features.append(-1 if re.search(ip_pattern, url) else 1)
        # 2. URL_Length
        if len(url) < 54:
            features.append(1)
        elif 54 <= len(url) <= 75:
            features.append(0)
        else:
            features.append(-1)
        # 3. Shortining_Service
        features.append(-1 if re.search(self.shortening_services, url) else 1)
        # 4. having_At_Symbol
        features.append(-1 if "@" in url else 1)
        # 5. double_slash_redirecting
        features.append(-1 if url.rfind('//') > 7 else 1)
        # 6. Prefix_Suffix
        features.append(-1 if '-' in hostname else 1)
        # 7. having_Sub_Domain
        temp_hostname = hostname.replace("www.", "")
        dot_count = temp_hostname.count('.')
        if dot_count == 1:
            features.append(1)
        elif dot_count == 2:
            features.append(0)
        else:
            features.append(-1)
        # 8. SSLfinal_State
        features.append(1 if parsed_url.scheme == 'https' else -1)
        # 9. Domain_registeration_length
        try:
            domain_info = self._safe_whois(hostname)
            if domain_info:
                expiration_date = domain_info.expiration_date
            if isinstance(expiration_date, list): expiration_date = expiration_date[0]
            if expiration_date:
                days_left = (expiration_date - datetime.now()).days
                features.append(1 if days_left > 365 else -1)
            else:
                features.append(-1)
        except:
            features.append(-1)
        # 10. HTTPS_token
        features.append(-1 if "https" in hostname.lower() else 1)
        # 11. Abnormal_URL
        features.append(1 if hostname in url else -1)
        # 12. port
        if parsed_url.port and parsed_url.port not in [80, 443]:
            features.append(-1)
        else:
            features.append(1)
        # Retrieve HTML and analyze HTML-based features
        html_features = self.extract_html_js_features_robust(url, timeout)
        
        # 13. Favicon
        features.append(html_features['Favicon'])
        # 14. Request_URL
        features.append(html_features['Request_URL'])
        # 15. URL_of_Anchor
        features.append(html_features['URL_of_Anchor'])
        # 16. links_in_tags
        features.append(html_features['Links_in_tags'])
        # 17. sfh
        features.append(html_features['SFH'])
        # 18. submit_email
        features.append(html_features['Submitting_to_email'])
        # 19. Redirect
        features.append(html_features['Redirect'])
        # 20. onmouseover
        features.append(html_features['on_mouseover'])
        # 21. right_click
        features.append(html_features['RightClick'])
        # 22. popup_window
        features.append(html_features['popUpWindow'])
        # 23. iframe
        features.append(html_features['Iframe'])
        # 24. Links_pointing_to_page
        features.append(html_features['Links_pointing_to_page'])
        # 25. age_of_domain
        domain_age_days = self.get_domain_age(self.get_base_domain(url))
        if domain_age_days is not None and domain_age_days > 180:
            features.append(1)
        else:
            features.append(-1)
        
        # 26. dns_record
        features.append(self.has_dns_record(self.get_base_domain(url)))
        # 27. web_traffic
        features.append(self.get_web_traffic(self.get_base_domain(url)))
        # 28. google_index
        features.append(self.is_google_indexed(self.get_base_domain(url)))
        # 29. statistical_report
        features.append(1)
        return features
    def get_domain_age(self, domain):
        try:
            w = self._safe_whois(domain)
            if w:
                creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                return (datetime.now() - creation).days
            return None
        except:
            return None
    def has_dns_record(self, domain):
        try:
            socket.gethostbyname(domain)
            return 1
        except:
            return -1
    def get_web_traffic(self, domain):
        if not self.top_domains:
            return 0  # If top domains file wasn't loaded, return suspicious (0)
        if domain in self.top_domains:
            return 1  # Popular -> Legitimate
        else:
            return -1 # Not popular -> Phishing
    def is_google_indexed(self, domain):
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            url = f"https://www.google.com/search?q=site:{domain}"
            response = requests.get(url, headers=headers, timeout=5)
            if "did not match any documents" in response.text.lower():
                return -1
            return 1
        except:
            return 1
    def get_redirect_chain_length(self, url, timeout=10):
        try:
            session = requests.Session()
            resp = session.get(url, timeout=timeout, allow_redirects=True)
            return len(resp.history)
        except:
            return -1
    def extract_html_js_features_robust(self, url, timeout=10):
        features = {
            "Favicon": 1, "Request_URL": 1, "URL_of_Anchor": 1, "Links_in_tags": 1,
            "SFH": 1, "Submitting_to_email": 1, "Redirect": 1, "on_mouseover": 1,
            "RightClick": 1, "popUpWindow": 1, "Iframe": 1, "Links_pointing_to_page": 1,
        }
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
            if response.status_code != 200:
                return features
            try:
                soup = BeautifulSoup(response.content, 'lxml') # Much faster
            except Exception:
                soup = BeautifulSoup(response.content, 'html.parser')
            base_domain = self.get_base_domain(response.url)
            html_content = response.text
            # 1. Favicon
            link_icon = soup.find('link', rel=re.compile("icon", re.I))
            if not link_icon or not link_icon.get('href'):
                features['Favicon'] = 1  # Standard
            else:
                favicon_url = urljoin(response.url, link_icon['href'])
                features['Favicon'] = 1 if self.get_base_domain(favicon_url) == base_domain else -1
            # 2. Request_URL
            media_tags = soup.find_all(['img', 'video', 'audio'])
            if not media_tags:
                features['Request_URL'] = 1
            else:
                mismatch = sum(1 for tag in media_tags if tag.get('src') and self.get_base_domain(urljoin(response.url, tag['src'])) != base_domain)
                perc = (mismatch / len(media_tags)) * 100
                if perc < self.THRESHOLDS['request_url'][0]:
                    features['Request_URL'] = 1
                elif perc <= self.THRESHOLDS['request_url'][1]:
                    features['Request_URL'] = 0
                else:
                    features['Request_URL'] = -1
            # 3. URL_of_Anchor
            anchors = soup.find_all('a')
            if not anchors:
                features['URL_of_Anchor'] = 1
            else:
                unsafe = 0
                for a in anchors:
                    href = a.get('href', '').strip()
                    if not href: continue
                    if href.startswith('#') or 'javascript:' in href.lower():
                        unsafe += 1
                    else:
                        full_url = urljoin(response.url, href)
                        if self.get_base_domain(full_url) != base_domain:
                            unsafe += 1
                perc = (unsafe / len(anchors)) * 100
                if perc < self.THRESHOLDS['url_of_anchor'][0]:
                    features['URL_of_Anchor'] = 1
                elif perc <= self.THRESHOLDS['url_of_anchor'][1]:
                    features['URL_of_Anchor'] = 0
                else:
                    features['URL_of_Anchor'] = -1
            # 4. Links_in_tags
            link_tags = soup.find_all(['meta', 'script', 'link', 'iframe', 'embed', 'object', 'source'])
            valid_count = mismatch = 0
            for tag in link_tags:
                link = tag.get('href') or tag.get('src') or tag.get('data')
                if link:
                    valid_count += 1
                    if self.get_base_domain(urljoin(response.url, link)) != base_domain:
                        mismatch += 1
            if valid_count == 0:
                features['Links_in_tags'] = 1
            else:
                perc = (mismatch / valid_count) * 100
                if perc < self.THRESHOLDS['links_in_tags'][0]:
                    features['Links_in_tags'] = 1
                elif perc <= self.THRESHOLDS['links_in_tags'][1]:
                    features['Links_in_tags'] = 0
                else:
                    features['Links_in_tags'] = -1
            # 5. SFH
            forms = soup.find_all('form')
            if not forms:
                features['SFH'] = 1
            else:
                has_empty = has_external = False
                for form in forms:
                    action = form.get('action', '').strip().lower()
                    if action in ['', 'about:blank']:
                        has_empty = True
                    elif self.get_base_domain(urljoin(response.url, action)) != base_domain:
                        has_external = True
                if has_empty: features['SFH'] = -1
                elif has_external: features['SFH'] = 0
                else: features['SFH'] = 1
            # 6. Submitting_to_email
            features['Submitting_to_email'] = -1 if re.search(r"mailto:|mail\(", html_content, re.I) else 1
            # 7. Redirect
            n_redirects = len(response.history) + len(re.findall(r"window\.location\.(?:replace|href)\s*=", html_content))
            if n_redirects <= self.THRESHOLDS['redirect'][0]: features['Redirect'] = 1
            elif n_redirects <= self.THRESHOLDS['redirect'][1]: features['Redirect'] = 0
            else: features['Redirect'] = -1
            # 8. on_mouseover
            features['on_mouseover'] = -1 if re.search(r"onmouseover\s*=\s*['\"].*window\.status.*['\"]", html_content, re.I) else 1
            # 9. RightClick
            features['RightClick'] = -1 if ("event.button==2" in html_content.replace(" ", "") or "contextmenu" in html_content.lower()) else 1
            # 10. popUpWindow
            features['popUpWindow'] = -1 if re.search(r"window\.open\s*\(", html_content) else 1
            # 11. Iframe
            iframe = soup.find('iframe')
            if not iframe:
                features['Iframe'] = 1
            else:
                src = iframe.get('src')
                features['Iframe'] = -1 if src and self.get_base_domain(urljoin(response.url, src)) != base_domain else 1
            # 12. Links_pointing_to_page
            domain = self.get_base_domain(url)
            redirect_cnt = self.get_redirect_chain_length(url, timeout)
            age = self.get_domain_age(domain)
            shortened = any(s in url.lower() for s in ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly'])
            
            risk_score = 0
            if redirect_cnt > 2: risk_score += 1
            if age is not None and age < 30: risk_score += 1
            if shortened: risk_score += 1
            
            if risk_score >= 2: features['Links_pointing_to_page'] = -1
            elif risk_score == 1: features['Links_pointing_to_page'] = 0
            else: features['Links_pointing_to_page'] = 1
        except:
            pass
        return features
