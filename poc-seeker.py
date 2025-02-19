#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import os
import sys
import re
import time
import json
import random
import httpx
from tqdm import tqdm
from datetime import datetime, timezone, timedelta

class PocSeeker:
    def __init__(self, cve=None, github_token=None, nvd_key=None, days=1):
        self.cve = None if not cve else cve.upper()
        self.nvd_key = nvd_key
        self.github_token = github_token
        self.days = days
        self.potential_findings = {} 
        self.have_a_look = {}
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:85.0) Gecko/20100101 Firefox/85.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0",
        ]
        self.ext = [".py", ".rb", ".pl", ".sh", ".ps1", ".bat", ".js", ".php", ".c", ".cpp", ".go", ".lua", ".rs", ".swift"]
        self.sources = ["github", "sploitus", "packetstormsecurity"]
        self.random_ua = random.choice(self.user_agents)
        self.h2client = httpx.Client(http2=True, verify=False, timeout=30)
        self.client = httpx.Client(verify=False, timeout=30)
        self.beijing_tz = timezone(timedelta(hours=8))

    def __del__(self):
        self.client.close()
        self.h2client.close()

    def nvd_collect_information(self):
        if not self.cve:
            print("No CVE provided")
            return None

        print(f"collect details for {self.cve} ...")
        cve_detail = None
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={self.cve}"
            headers = {}
            if self.nvd_key:
                headers["apiKey"] = self.nvd_key
            response = self.client.get(url, headers=headers)
            data = response.json()
            total_results = data.get('totalResults', 0)
            if data and total_results != 0:
                cve_detail = {}
                cve_detail["id"] = data['vulnerabilities'][0]['cve'].get('id')
                cve_detail["desc"] = data['vulnerabilities'][0]['cve']['descriptions'][0].get('value')
                cve_detail["v3metric"] = data['vulnerabilities'][0]['cve'].get('metrics', {}).get('cvssMetricV31', [])
                cve_detail["base_score"] = cve_detail["v3metric"][0]['cvssData']['baseScore'] if cve_detail["v3metric"] else None
                cve_detail["vector"] = cve_detail["v3metric"][0]['cvssData'].get('vectorString') if cve_detail["v3metric"] else None
                cve_detail["exploitabilityScore"] = cve_detail["v3metric"][0]['exploitabilityScore'] if cve_detail["v3metric"] else None
                cve_detail["impactScore"] = cve_detail["v3metric"][0]['impactScore'] if cve_detail["v3metric"] else None
        except Exception as e:
            print(f"Error collecting NVD information: {e}")
        
        return cve_detail

    def check_github_repo(self, repo, headers):
        quality = 0

        try:
            url_content = f"https://api.github.com/repos/{repo}/contents"
            resp = self.h2client.get(url_content, headers=headers)
            file_list = []
            if resp.status_code == 200:
                contents = resp.json()
                for cont in contents:
                    file_list.append(cont.get("name", ""))
            else:
                return quality
        except Exception:
            return quality

        repo_with_readme = any(re.search(r"README\.md", fname, re.IGNORECASE) for fname in file_list)
        required_extension_found = any(any(fname.endswith(ext) for ext in self.ext) for fname in file_list)
        cve_found = False
        if repo_with_readme:
            readme_url_main = f"https://raw.githubusercontent.com/{repo}/main/README.md"
            readme_url_master = f"https://raw.githubusercontent.com/{repo}/master/README.md"
            try:
                r = self.client.get(readme_url_main)
                if r.status_code != 200:
                    r = self.client.get(readme_url_master)
                if r.status_code == 200:
                    if self.cve:
                        if self.cve in r.text.upper():
                            cve_found = True
                    else:
                        if "CVE" in r.text.upper():
                            cve_found = True
            except:
                pass

        if required_extension_found and cve_found:
            quality = 2
        else:
            quality = 1
        
        return quality

    def add_finding(self, cve, quality, info):
        if quality == 2:
            if self.potential_findings.get(cve):
                for i in self.potential_findings[cve]:
                    if i["link"] == info["link"]:
                        return
            else:
                self.potential_findings[cve] = []
            self.potential_findings[cve].append(info)
        elif quality == 1:
            if self.have_a_look.get(cve):
                for i in self.have_a_look[cve]:
                    if i["link"] == info["link"]:
                        return
            else:
                self.have_a_look[cve] = []
            self.have_a_look[cve].append(info)

    def github_search(self):
        if not self.cve:
            print("No CVE provided")
            return None

        headers = {"Accept": "application/vnd.github+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
        try:
            url = f"https://api.github.com/search/repositories?q={self.cve}+in:name,description&sort=updated&order=desc"
            resp = self.h2client.get(url, headers=headers)
            data = resp.json()
            items = data.get("items", [])
        except Exception as e:
            print(f"Error searching GitHub repositories: {e}")

        for item in tqdm(items, desc="Searching GitHub repositories", unit="repo"):
            info = {}
            info["id"] = self.cve
            info["name"] = item["full_name"]
            info["src"] = "github"
            info["desc"] = item["description"]
            info["link"] = item["html_url"]
            push_time = datetime.strptime(item["pushed_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).astimezone(self.beijing_tz)
            info["time"] = push_time.strftime("%Y-%m-%d %H:%M:%S")
            quality = self.check_github_repo(item["full_name"], headers)
            self.add_finding(self.cve, quality, info)

    def sploitus_search(self):
        if not self.cve:
            print("No CVE provided")
            return None

        offset = 0
        max_items = 20
        sploitus_exp = []
        print(f"Searching sploitus for {self.cve} ...")
        while True:
            try:
                payload = {
                    "type": "exploits",
                    "sort": "default",
                    "query": self.cve,
                    "title": False,
                    "offset": offset
                }
                headers = {
                    "Host": "sploitus.com",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "User-Agent": random.choice(self.user_agents),
                    "Accept-Language": "en-US,en;q=0.9"
                }

                resp = self.h2client.post("https://sploitus.com/search", json=payload, headers=headers)
                if resp.status_code != 200:
                    print("Searching sploitus failed")
                    break
                data = resp.json()
                exploits = data.get("exploits", [])
                if not exploits:
                    break
                for exploit in tqdm(exploits, desc=f"Searching sploitus offset {offset}", unit="exp"):
                    info = {}
                    info["id"] = self.cve
                    info["name"] = exploit.get("title", "")
                    info["src"] = "sploitus"
                    info["desc"] = exploit.get("source", "")
                    info["link"] = exploit.get("href", "")
                    info["time"] = exploit.get("published", "")
                    if re.search(self.cve, info["desc"], re.IGNORECASE):
                        self.add_finding(self.cve, 2, info)
                    else:
                        self.add_finding(self.cve, 1, info)

                offset += 10
                if offset > max_items:
                    break
            except Exception as e:
                print(f"Error in sploitus search: {e}")
                break

            return sploitus_exp

    def search(self):
        if not self.cve:
            print("No CVE provided")
            return None

        print(f"I am searching for {self.cve} POC, hold on ...")

        self.clear_findings()

        for src in self.sources:
            if src == "github":
                self.github_search()
            elif src == "sploitus":
                self.sploitus_search()

        return {"good": self.potential_findings, "doubt": self.have_a_look}

    def set_sources(self, sources):
        srclist = []
        list_sources = sources.split(",")
        for src in list_sources:
            if src in self.sources:
                srclist.append(src)
            else:
                print(f"Opsss ! you provided a non valid source [ {src} ]")
        self.sources = srclist
    
    def set_cve(self, cve):
        self.cve = cve.upper()
    
    def set_github_token(self, github_token):
        self.github_token = github_token
    
    def set_nvd_key(self, nvd_key):
        self.nvd_key = nvd_key
    
    def set_days(self, days):
        self.days = days
    
    def clear_findings(self):
        self.potential_findings = {}
        self.have_a_look = {}

    def updates(self):
        self.clear_findings()

        current_time = datetime.now(self.beijing_tz)
        headers = {"Accept": "application/vnd.github+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
        
        page = 1
        total_processed = 0
        
        try:
            while True:
                url = f"https://api.github.com/search/repositories?q=CVE&sort=updated&order=desc&per_page=100&page={page}"
                resp = self.h2client.get(url, headers=headers)
                data = resp.json()
                items = data.get("items", [])
                if not items:
                    break

                for item in tqdm(items, desc=f"Processing Page {page}", unit="repo"):
                    # 验证仓库名称或描述中是否包含完整的CVE编号
                    name = str(item.get("name", ""))
                    description = str(item.get("description", ""))
                    
                    cve_pattern = r'CVE-\d{4}-\d{4,}'
                    found_cve = re.search(cve_pattern, name + " " + description, re.IGNORECASE)
                    if not found_cve:
                        continue

                    push_time = datetime.strptime(item["pushed_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).astimezone(self.beijing_tz)
                    # 检查是否在指定的时间范围内
                    days_diff = (current_time - push_time).days
                    if days_diff > self.days:
                        return {"good": self.potential_findings, "doubt": self.have_a_look}
                        
                    info = {}
                    info["id"] = found_cve.group()
                    info["name"] = item["full_name"]
                    info["src"] = "github"
                    info["desc"] = item["description"]
                    info["link"] = item["html_url"]
                    info["time"] = push_time.strftime("%Y-%m-%d %H:%M:%S")
                    quality = self.check_github_repo(item["full_name"], headers)
                    self.add_finding(info["id"], quality, info)
                    total_processed += 1

                page += 1
                time.sleep(1)
                        
                # GitHub 搜索API限制：最多返回1000个结果
                if page > 10 or total_processed >= 1000:
                    print("\nReached GitHub's search result limit (1000 items)")
                    break
        except Exception as e:
            print(f"Error searching GitHub repositories: {e}")
        
        return {"good": self.potential_findings, "doubt": self.have_a_look}
    
    def print_results(self):
        if self.potential_findings:
            print("\nPotential POCs found:")
            for k, v in self.potential_findings.items():
                print(json.dumps(v, indent=2))

        if self.have_a_look:
            print("\nPossible related links:")
            for k, v in self.have_a_look.items():
                print(json.dumps(v, indent=2))
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Search for POC of CVE')
    parser.add_argument('-q', '--query', type=str, help='CVE number to search for')
    parser.add_argument('-u', '--update', type=int, default=1, help='fetch POCs from N days ago until now')
    parser.add_argument('-s', '--source', type=str, help='Search sources separated by comma (github,sploitus)')
    parser.add_argument('--github-token', type=str, help='GitHub access token')
    parser.add_argument('--nvd-key', type=str, help='NVD API key')
    parser.add_argument('--enable-nvd', action='store_true', help='Enable NVD information collection')
    args = parser.parse_args()

    # 验证CVE格式
    if args.query:
        cve_match = re.search(r'CVE-\d{4}-\d{4,}', args.query, re.IGNORECASE)
        if not cve_match:
            print("Error: Invalid CVE format. Example: CVE-2023-12345")
            sys.exit(1)
    
        cve = cve_match.group(0)
    
        # 创建PocSeeker实例
        seeker = PocSeeker(
            cve=cve,
            github_token=args.github_token,
            nvd_key=args.nvd_key
        )
    else:
        seeker = PocSeeker(
            github_token=args.github_token,
            nvd_key=args.nvd_key,
            days=args.update
        )

    # 设置搜索源
    if args.source:
        seeker.set_sources(args.source)
        if not seeker.sources:
            print("Error: No valid sources provided")
            print("Available sources: github, sploitus, vulnerability-lab, packetstormsecurity")
            sys.exit(1)
        print(f"Using sources: {', '.join(seeker.sources)}")

    # 获取NVD信息
    if args.query and args.enable_nvd:
        cve_detail = seeker.nvd_collect_information()
        if cve_detail:
            print("\nCVE Details:")
            print("-" * 50)
            if cve_detail.get("id"): print(f"CVE ID: {cve_detail['id']}")
            if cve_detail.get("desc"): print(f"Description: {cve_detail['desc']}")
            if cve_detail.get("vector"): print(f"Vector: {cve_detail['vector']}")
            if cve_detail.get("base_score"): print(f"Base Score: {cve_detail['base_score']}")
            if cve_detail.get("exploitabilityScore"): print(f"Exploitability Score: {cve_detail['exploitabilityScore']}")
            if cve_detail.get("impactScore"): print(f"Impact Score: {cve_detail['impactScore']}")
            print("-" * 50)
            print()
        else:
            print("No NVD information found")
            sys.exit(1)

    # 搜索POC
    if args.query:
        seeker.search()
        seeker.print_results()
    elif args.update:
        seeker.updates()
        seeker.print_results()
