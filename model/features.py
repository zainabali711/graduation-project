import re 
import math 
from urllib.parse import urlparse 
from collections import Counter

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gp',
    '.xyz', '.top', '.pw', '.cc', '.su'
]

URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co',
    'goo.gl', 'ow.ly', 'is.gd'
]

def calculate_entropy(text):
    if not text:
        return 0
    freq = Counter(text)
    length = len(text)
    return -sum(
        (c / length) * math.log2(c / length)
        for c in freq.values()
    )
def extract_features(url):
    try:
        if not url.startwith(("http://", "https://")):
            url = "https://" + url

        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query

        return {
            "url_length": len(url),
            "domain_length": len(domain),
            "num_digits": sum(c.isdigit() for c in url),
            "num_special_chars":len(re.findall(r'[-_@?=&%#+~]', url)),
            "num_dots": url.count('.'),
            "num_hyphens": url.count('-'),
            "num_slashes": url.count('/'),
            "subdomain_count": max(len(domain.split('.')) - 2, 0),
            "has_ip_address": 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0,
            "has_at_symbol": 1 if '@' in url else 0,
            "has_double_slash": 1 if '//' in url[7:] else 0,
            "tld_suspicious": 1 if any(domain.endswith(t) for t in SUSPICIOUS_TLDS) else 0,
            "entropy": round(calculate_entropy(domain), 4),
            "digit_ratio": round(sum(c.isdigit() for c in url) / max(len(url), 1), 4),
            "has_https": 1 if url.startswith('https') else 0,
            "path_length": len(path),
            "query_length": len(query),
            "num_params": len(query.split('&')) if query else 0,
            "is_shortened": 1 if any(s in domain for s in URL_SHORTENERS) else 0,
            "has_port": 1 if ':' in domain else 0,
        }
    except:
        return None
    