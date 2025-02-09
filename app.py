from flask import Flask, request, jsonify, render_template
import requests
import base64
import re
import json
import time
import os
import random
import socket
import urllib3
import whois
from tor_proxy import get_tor_session
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

CAPMONSTER_API_KEY = "API_KEY"
BLOCKLIST_CACHE_FILE = "blocklist_cache.txt"
CACHE_EXPIRY_TIME = 3600

blocked_domains = set()

def load_blocklist(url):
    current_time = time.time()
    if os.path.exists(BLOCKLIST_CACHE_FILE):
        cache_age = current_time - os.path.getmtime(BLOCKLIST_CACHE_FILE)
        if cache_age < CACHE_EXPIRY_TIME:
            with open(BLOCKLIST_CACHE_FILE, 'r') as file:
                return set(file.read().splitlines())
    try:
        response = requests.get(url)
        if response.status_code == 200:
            blocklist = set(line.decode('utf-8').strip() for line in response.iter_lines())
            with open(BLOCKLIST_CACHE_FILE, 'w') as cache_file:
                cache_file.write("\n".join(blocklist))
            return blocklist
        else:
            return set()
    except requests.RequestException:
        return set()

blocklist_url = "https://raw.githubusercontent.com/Bon-Appetit/porn-domains/refs/heads/master/block.txt"
blocked_domains = load_blocklist(blocklist_url)

app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

def select_random_user_agent(file_path):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            if not lines:
                raise ValueError("The file is empty")
            return random.choice(lines).strip()
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' does not exist.")
    except ValueError as ve:
        print(ve)

def get_turnstile_token(site_url, site_key):
    create_task_url = "https://api.capmonster.cloud/createTask"
    data = {
        "clientKey": CAPMONSTER_API_KEY,
        "task": {
            "type": "TurnstileTaskProxyless",
            "websiteURL": site_url,
            "websiteKey": site_key
        }
    }
    response = requests.post(create_task_url, json=data)
    if response.status_code != 200:
        return None
    result = response.json()
    task_id = result.get("taskId")
    if not task_id:
        return None
    get_result_url = "https://api.capmonster.cloud/getTaskResult"
    for _ in range(30):
        data = {"clientKey": CAPMONSTER_API_KEY, "taskId": task_id}
        result = requests.post(get_result_url, json=data)
        if result.status_code != 200:
            return None
        res = result.json()
        if res.get("status") == "processing":
            time.sleep(5)
            continue
        elif res.get("status") == "ready":
            return res.get("solution", {}).get("token")
        else:
            return None
    return None

def upload_image(base64_image, use_tor=False):
    try:
        data = {"image": base64_image}
        url = "https://pimeyes.com/api/upload/file"
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if use_tor:
            session = get_tor_session()
            response = session.post(url, headers=headers, json=data, verify=False)
        else:
            response = requests.post(url, headers=headers, json=data, verify=False)
        if response.status_code == 200:
            print("Image uploaded successfully.")
            if not response.json().get("faces"):
                print("No faces found in uploaded image.")
                return None, None
            return response.cookies, response.json().get("faces")[0]["id"]
        else:
            print(f"Failed to upload image. Status code: {response.status_code}")
            return None, None
    except Exception as e:
        print(f"Error uploading image: {e}")
        return None, None

def exec_search(cookies, search_id, user_agent, use_tor=False):
    headers = {
        'sec-ch-ua':'"Not;A=Brand";v="99", "Chromium";v="106"',
        'accept':'application/json, text/plain, */*',
        'content-type':'application/json',
        'sec-ch-ua-mobile': '?0',
        'user-agent': user_agent,
        'origin': 'https://pimeyes.com',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'referer': 'https://pimeyes.com/en',
        'accept-encoding':'gzip, deflate',
        'accept-language':'en-US,en;q=0.9'
    }
    url = "https://pimeyes.com/api/search/new"
    token = get_turnstile_token("https://pimeyes.com/en", "0x4AAAAAAA6kcejno0Qiz9et")
    data = {
        "faces": [search_id],
        "time": "any",
        "type": "PREMIUM_SEARCH",
        "g-recaptcha-response": token if token else ""
    }
    if use_tor:
        session = get_tor_session()
        response = session.post(url, headers=headers, json=data, cookies=cookies)
    else:
        response = requests.post(url, headers=headers, json=data, cookies=cookies)
    if response.status_code == 200:
        json_response = response.json()
        return json_response.get("searchHash"), json_response.get("searchCollectorHash")
    else:
        print(f"Failed to get searchHash. Status code: {response.status_code}")
        print(response.text)
        return None, None

def extract_url_from_html(html_content):
    pattern = r'api-url="([^"]+)"'
    url = re.search(pattern, html_content)
    if url:
        url = url.group(1)
        return re.search(r'https://[^\"]+', url).group()
    return None

def find_results(search_hash, search_collector_hash, search_id, cookies, use_tor=False):
    try:
        url = f"https://pimeyes.com/en/results/{search_collector_hash}_{search_hash}?query={search_id}"
        if use_tor:
            session = get_tor_session()
            response = session.get(url, cookies=cookies)
        else:
            response = requests.get(url, cookies=cookies)
        if response.status_code == 200:
            print("Found correct server.")
            return extract_url_from_html(response.text)
        else:
            print(f"Failed to find results. Status code: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error finding results: {str(e)}")
        return None

def get_results(url, search_hash, user_agent):
    try:
        data = {
            "hash": search_hash,
            "limit": 250,
            "offset": 0,
            "retryCount": 0
        }
        headers = {
            'sec-ch-ua':'"Not;A=Brand";v="99", "Chromium";v="106"',
            'accept':'application/json, text/plain, */*',
            'content-type':'application/json',
            'sec-ch-ua-mobile': '?0',
            'user-agent': user_agent,
            'origin': 'https://pimeyes.com',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            'referer': 'https://pimeyes.com/en',
            'accept-encoding':'gzip, deflate',
            'accept-language':'en-US,en;q=0.9'
        }
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            print("Results obtained successfully.")
            return response.json()
        else:
            print(f"Failed to obtain results. Status code: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error getting results: {str(e)}")
        return None

def hex_to_ascii(hex_string):
    try:
        hex_string = hex_string.lstrip('0x')
        bytes_data = bytes.fromhex(hex_string)
        return bytes_data.decode('ascii', errors='ignore')
    except Exception:
        return ""

def normalize_domain(domain):
    domain = domain.lower()
    subdomains_to_remove = ['www.', 'pic.', 'static.', 'm.', 'cdn.', 'api.', 'public.']
    for sub in subdomains_to_remove:
        if domain.startswith(sub):
            domain = domain[len(sub):]
            break
    return domain

def classify_site(url):
    domain = re.search(r'https?://([^/]+)', url).group(1)
    normalized_domain = normalize_domain(domain)
    if is_adult_site(url):
        return "Adult Site"
    elif classify_site_with_whois(domain) == "Social E-Commerce Site":
        return "Social E-Commerce Site"
    return "Unclassified Site"

def is_adult_site(url):
    domain = re.search(r'https?://([^/]+)', url)
    if domain:
        domain = domain.group(1)
        if domain in blocked_domains:
            return True
    return False

def is_social_e_commerce_site(url):
    social_sites = [
        'pinterest.com', 'instagram.com', 'facebook.com', 'etsy.com',
        'poshmark.com', 'depop.com', 'mercari.com', 'letgo.com',
        'offerup.com', 'carousell.com', 'vinted.com', 'thredup.com',
        'tradesy.com', 'grailed.com', 'reverb.com', 'jet.com',
        'socialshopwave.com', 'shoploop.app', 'verishop.com', 'wanelo.com',
        'fancy.com', 'polyvore.com', 'liketoknow.it', 'shopstyle.com',
        'keep.com', 'lyst.com', 'mightybuy.co', 'yelpextensions.com',
        'shpock.com', 'rumgr.com', 'curtsyapp.com', '5miles.com',
        'swappa.com', 'wallapop.com'
    ]
    return any(site in url for site in social_sites)

def resolve_domain_whois(domain):
    try:
        domain_info = whois.whois(domain)
        return domain_info
    except Exception as e:
        print(f"Error resolving domain: {e}")
        return None

def classify_site_with_whois(domain):
    if "etsystatic.com" in domain:
        return "etsy.com"
    if domain.endswith("etsy.com"):
        return "etsy.com"
    if "." in domain:
        base_domain = domain.split('.')[-2] + '.' + domain.split('.')[-1]
        if base_domain == "etsy.com":
            return "etsy.com"
    domain_info = resolve_domain_whois(domain)
    if not domain_info:
        return "Unclassified Site"
    if is_social_e_commerce_site(domain):
        return "Social E-Commerce Site"
    return "Unclassified Site"

def process_thumbnails(json_data):
    results = json_data.get('results', [])
    if not results:
        print("Search successful, but no matches found.")
        return

    processed_results = []
    for result in results:
        thumbnail_url = result.get('thumbnailUrl', '')
        print(f"Thumbnail URL: {thumbnail_url}")

        if thumbnail_url.startswith("data:"):
            print("Data URL present, using directly.")
            continue

        match = re.search(r'/proxy/([0-9a-fA-F]+)', thumbnail_url)
        if match:
            hex_part = match.group(1)
            ascii_text = hex_to_ascii(hex_part)
            try:
                decoded = json.loads(ascii_text)
                page_url = decoded.get('url')
                if page_url:
                    print(f"Extracted Page URL: {page_url}")
                    
                    # Pobieranie nazwy strony (site)
                    site = result.get('site', '')
                    if not site:
                        m_site = re.search(r'https?://([^/]+)', page_url)
                        site = m_site.group(1) if m_site else "Unknown site"
                    
                    # Ekstrakcja domeny z page_url
                    m_domain = re.search(r'https?://([^/]+)', page_url)
                    domain = m_domain.group(1) if m_domain else ''
                    
                    # Uzyskanie resolved_domain – funkcja może dodatkowo modyfikować domenę
                    resolved_domain = classify_site_with_whois(domain) if domain else "Unknown"
                    
                    print(f"Resolved Domain: {resolved_domain}")
                    
                    # Dodatkowe informacje (opcjonalnie)
                    is_adult = is_adult_site(page_url)
                    is_social_e_commerce = is_social_e_commerce_site(page_url)
                    
                    processed_results.append({
                        "page_url": page_url,
                        "account_info": result.get('accountInfo', 'Not available'),
                        "thumbnail_url": thumbnail_url,
                        "site": site,
                        "resolved_domain": resolved_domain,
                        "is_adult": is_adult,
                        "is_social_e_commerce": is_social_e_commerce
                    })
                else:
                    print("No URL found in decoded data.")
            except json.JSONDecodeError:
                if "http" in ascii_text:
                    print(f"ASCII URL: {ascii_text}")
                else:
                    print(f"Error decoding JSON for thumbnail: {thumbnail_url}")
    return processed_results


@app.route("/", methods=["GET", "POST"])
def index():
    use_tor = request.form.get("use_tor") == "on"
    tor_ip = None
    if use_tor:
        tor_session = get_tor_session()
        try:
            tor_ip = tor_session.get("ip", "Unknown")
        except Exception:
            tor_ip = "Unknown"
    if request.method == "POST":
        file = request.files.get("file")
        pasted_image = request.form.get("pasted_image")
        if not file and not pasted_image:
            return render_template("index.html", error="No selected file or pasted image", tor_ip=tor_ip)
        if file:
            base64_image = base64.b64encode(file.read()).decode("utf-8")
            base64_image = f"data:image/jpeg;base64,{base64_image}"
        elif pasted_image:
            base64_image = re.sub("^data:image/.+;base64,", "", pasted_image)
            base64_image = f"data:image/jpeg;base64,{base64_image}"
        cookies, search_id = upload_image(base64_image, use_tor)
        if not cookies or not search_id:
            return render_template("index.html", error="Failed to upload image", tor_ip=tor_ip)
        cookies.set("payment_gateway_v3", "fastspring", domain="pimeyes.com")
        cookies.set("uploadPermissions", str(int(time.time()*1000))[:13], domain="pimeyes.com")
        user_agent = select_random_user_agent("user-agents.txt")
        search_hash, search_collector_hash = exec_search(cookies, search_id, user_agent, use_tor)
        if not (search_hash and search_collector_hash):
            return jsonify({"error": "Could not proceed with further API calls."}), 404
        server_url = find_results(search_hash, search_collector_hash, search_id, cookies, use_tor)
        if not server_url:
            return jsonify({"error": "Failed to find server URL."}), 404
        res = get_results(server_url, search_hash, user_agent)
        if res:
            process_thumbnails(res)
            return render_template('results.html', tor_ip=tor_ip)
        else:
            return render_template('index.html', error="Failed to get results", tor_ip=tor_ip)
    return render_template('index.html', tor_ip=tor_ip)

def find_available_port(start_port=5000, max_port=65535):
    for port in range(start_port, max_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('localhost', port))
                return port
            except socket.error:
                continue
    return None

if __name__ == '__main__':
    blocked_domains = load_blocklist(blocklist_url)
    port = find_available_port()
    if port:
        print(f"Starting server on port {port}")
        app.run(debug=True, port=port)
    else:
        print("No available ports found.")
