import requests
from rich.console import Console

console = Console()

class WAFDetector:
    def __init__(self, target_url):
        self.target_url = target_url
        self.waf_signatures = {
            "Cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
            "Akamai": ["akamai-ch", "akamai-ghost", "edge-cache-tag"],
            "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id", "aws-waf"],
            "Imperva": ["x-iinfo", "incap_ses", "visid_incap"],
            "F5 BIG-IP": ["x-cnection", "f5_cspm", "bigipserver"],
            "ModSecurity": ["mod_security", "no-cache=\"set-cookie\""]
        }

    def detect(self):
        """HTTP 헤더 및 응답 코드를 분석하여 WAF 식별"""
        try:
            # 1. 일반 요청
            res = requests.get(self.target_url, timeout=5, verify=False)
            
            # 2. 고의적 공격 페이로드 주입 (403 Forbidden 유도)
            malicious_url = f"{self.target_url}/?id=' OR 1=1--"
            res_attack = requests.get(malicious_url, timeout=5, verify=False)
            
            found_waf = "Unknown / No WAF"
            
            # 헤더 분석
            all_headers = str(res.headers).lower() + str(res_attack.headers).lower()
            for waf, sigs in self.waf_signatures.items():
                if any(sig.lower() in all_headers for sig in sigs):
                    found_waf = waf
                    break
            
            # 응답 코드 기반 추측
            if res_attack.status_code == 403 and found_waf == "Unknown / No WAF":
                found_waf = "Generic WAF detected (403 Block)"
                
            return found_waf
        except:
            return "Connection Failed"

def run_waf_detector(target):
    detector = WAFDetector(target)
    return detector.detect()
