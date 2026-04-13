#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# content_checker.py
"""
Content checker for opensquat.
Scrapes domains and assigns phishing probability scores based on keywords.
"""

import requests
import concurrent.futures
from bs4 import BeautifulSoup
from colorama import Fore, Style
import time
from urllib.parse import urlparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ContentChecker:
    def __init__(self, timeout=10, max_workers=10):
        """
        Initialize the content checker.
        
        Args:
            timeout: Request timeout in seconds
            max_workers: Maximum concurrent requests
        """
        self.timeout = timeout
        self.max_workers = max_workers
        
        # Spanish insurance-related keywords (case insensitive)
        self.keywords = [
            'seguros',
            'seguro',
            'credito',
            'crédito',
            'garantia',
            'garantía',
            'polizas',
            'pólizas',
            'vida',
            'cotizar',
            'cotización',
            'aseguradora',
            'prima',
            'indemnización',
            'cobertura'
        ]
        
        # Headers to mimic a real browser
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

    def fetch_content(self, domain):
        """
        Fetch webpage content from a domain.
        
        Args:
            domain: Domain name to check
            
        Returns:
            Tuple of (domain, content_text, status_code) or (domain, None, error_code)
        """
        urls_to_try = [
            f'http://{domain}',
            f'https://{domain}',
            f'http://www.{domain}',
            f'https://www.{domain}'
        ]
        
        for url in urls_to_try:
            try:
                response = requests.get(
                    url,
                    headers=self.headers,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False  # Skip SSL verification for suspicious sites
                )
                
                if response.status_code == 200:
                    # Parse HTML content
                    soup = BeautifulSoup(response.content, 'html.parser')
                    
                    # Remove script and style elements
                    for script in soup(['script', 'style', 'noscript']):
                        script.decompose()
                    
                    # Get text content
                    text = soup.get_text(separator=' ', strip=True)
                    
                    return (domain, text.lower(), 200)
                    
            except requests.exceptions.SSLError:
                continue
            except requests.exceptions.ConnectionError:
                continue
            except requests.exceptions.Timeout:
                continue
            except Exception as e:
                continue
        
        return (domain, None, 0)

    def calculate_score(self, domain, content):
        """
        Calculate phishing probability score based on keyword matches.
        
        Args:
            domain: Domain name
            content: Webpage text content (lowercase)
            
        Returns:
            Tuple of (score, matched_keywords, risk_level)
        """
        if content is None:
            return (0, [], "UNREACHABLE")
        
        matched_keywords = []
        keyword_count = 0
        
        # Count keyword occurrences
        for keyword in self.keywords:
            count = content.count(keyword)
            if count > 0:
                matched_keywords.append(f"{keyword}({count})")
                keyword_count += count
        
        # Calculate base score (0-100)
        if not matched_keywords:
            score = 0
            risk_level = "LOW"
        elif len(matched_keywords) == 1 and keyword_count <= 2:
            score = 25
            risk_level = "LOW"
        elif len(matched_keywords) <= 2 and keyword_count <= 5:
            score = 40
            risk_level = "MEDIUM"
        elif len(matched_keywords) <= 3 and keyword_count <= 10:
            score = 60
            risk_level = "MEDIUM-HIGH"
        elif len(matched_keywords) <= 5 or keyword_count <= 20:
            score = 75
            risk_level = "HIGH"
        else:
            score = 90
            risk_level = "CRITICAL"
        
        # Boost score if domain name contains "orsan"
        if 'orsan' in domain.lower():
            score = min(100, score + 15)
        
        # Recalculate risk level based on FINAL score (after bonus)
        if score == 0:
            risk_level = "NO KEYWORDS"
        elif score < 40:
            risk_level = "LOW"
        elif score < 60:
            risk_level = "MEDIUM"
        elif score < 75:
            risk_level = "MEDIUM-HIGH"
        elif score < 90:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"
        
        return (score, matched_keywords, risk_level)

    def check_domain(self, domain):
        """
        Check a single domain and return results.
        
        Args:
            domain: Domain to check
            
        Returns:
            Dictionary with domain info and score
        """
        print(f"{Fore.CYAN}[*] Checking: {domain}{Style.RESET_ALL}")
        
        domain_clean, content, status = self.fetch_content(domain)
        score, keywords, risk_level = self.calculate_score(domain_clean, content)
        
        result = {
            'domain': domain_clean,
            'score': score,
            'risk_level': risk_level,
            'keywords_found': keywords,
            'status': status,
            'reachable': content is not None
        }
        
        # Print result with correct colors matching risk levels
        if score >= 75:
            color = Fore.RED  # HIGH/CRITICAL
        elif score >= 60:
            color = Fore.YELLOW + Style.BRIGHT  # MEDIUM-HIGH
        elif score >= 40:
            color = Fore.YELLOW  # MEDIUM
        elif score > 0:
            color = Fore.GREEN  # LOW
        else:
            color = Fore.WHITE  # NO KEYWORDS
        
        if result['reachable']:
            print(f"{color}  └─ Score: {score}/100 [{risk_level}] - Keywords: {', '.join(keywords) if keywords else 'None'}{Style.RESET_ALL}")
        else:
            print(f"{Fore.WHITE}  └─ Unreachable{Style.RESET_ALL}")
        
        return result

    def check_domains(self, domain_list):
        """
        Check multiple domains concurrently.
        
        Args:
            domain_list: List of domain names
            
        Returns:
            List of result dictionaries, sorted by score (highest first)
        """
        if not domain_list:
            return []
        
        print(f"\n{Style.BRIGHT}{Fore.GREEN}+---------- Content Analysis ----------+{Style.RESET_ALL}")
        print(f"[*] Analyzing {len(domain_list)} domains for insurance-related content...")
        print(f"[*] Keywords: {', '.join(self.keywords[:8])}...\n")
        
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_domain = {
                executor.submit(self.check_domain, domain): domain 
                for domain in domain_list
            }
            
            for future in concurrent.futures.as_completed(future_to_domain):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    domain = future_to_domain[future]
                    print(f"{Fore.RED}[!] Error checking {domain}: {str(e)}{Style.RESET_ALL}")
        
        # Sort by score (highest first)
        results.sort(key=lambda x: x['score'], reverse=True)
        
        # Print summary
        high_risk = sum(1 for r in results if r['score'] >= 60)
        medium_risk = sum(1 for r in results if 40 <= r['score'] < 60)
        low_risk = sum(1 for r in results if 0 < r['score'] < 40)
        no_match = sum(1 for r in results if r['score'] == 0 and r['reachable'])
        unreachable = sum(1 for r in results if not r['reachable'])
        
        print(f"\n{Style.BRIGHT}[*] Content Analysis Summary:{Style.RESET_ALL}")
        print(f"    HIGH Risk (60-100):   {high_risk}")
        print(f"    MEDIUM Risk (40-59):  {medium_risk}")
        print(f"    LOW Risk (1-39):      {low_risk}")
        print(f"    No Keywords:          {no_match}")
        print(f"    Unreachable:          {unreachable}")
        
        return results

    def format_discord_message(self, date_string, results, min_score=0):
        """
        Format results for Discord message.
        
        Args:
            date_string: Date string for the message
            results: List of result dictionaries
            min_score: Minimum score to include in message
            
        Returns:
            Formatted string for Discord
        """
        filtered_results = [r for r in results if r['score'] >= min_score]
        
        if not filtered_results:
            return f"{date_string}\nNo domains found with score >= {min_score}"
        
        lines = [f"**{date_string} - Phishing Analysis Report**", ""]
        
        for result in filtered_results:
            risk_emoji = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM-HIGH': '🟡',
                'MEDIUM': '🟡',
                'LOW': '🟢',
                'UNREACHABLE': '⚪'
            }.get(result['risk_level'], '⚪')
            
            keywords_str = ', '.join(result['keywords_found'][:5]) if result['keywords_found'] else 'none'
            if len(result['keywords_found']) > 5:
                keywords_str += '...'
            
            line = f"{risk_emoji} **{result['domain']}** - Score: {result['score']}/100 [{result['risk_level']}]"
            if result['keywords_found']:
                line += f"\n   Keywords: {keywords_str}"
            
            lines.append(line)
        
        lines.append(f"\n**Total analyzed:** {len(results)} | **High risk:** {sum(1 for r in results if r['score'] >= 60)}")
        
        return '\n'.join(lines)


def main():
    """Test function"""
    test_domains = ['google.com', 'seguros-orsan.com', 'example.com']
    
    checker = ContentChecker()
    results = checker.check_domains(test_domains)
    
    print("\n" + "="*60)
    message = checker.format_discord_message("2025-12-04", results, min_score=0)
    print(message)


if __name__ == "__main__":
    main()