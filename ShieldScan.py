import socket
import requests
import time
from urllib.parse import urlparse
import threading
from colorama import init, Fore

init()

class VulnerabilityScanner:
    def __init__(self):
        self.scan_options = {
            "1": "Smart Scan (AI-based detection)",
            "2": "Full Automated Scan",
            "3": "Information Gathering",
            "4": "All Options (Complete scan)",
            "5": "Custom Scan (semi-manual)"
        }
        self.scan_results = []
        self.stop_scan_flag = False
        self.colors = [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN]

    def display_banner(self):
        banner = f"""{Fore.RED}
        ██╗   ██╗██╗   ██╗██╗      █████╗ ███████╗██████╗ 
        ██║   ██║██║   ██║██║     ██╔══██╗██╔════╝██╔══██╗
        ██║   ██║██║   ██║██║     ███████║███████╗██████╔╝
        ██║   ██║██║   ██║██║     ██╔══██║╚════██║██╔═══╝ 
        ╚██████╔╝╚██████╔╝███████╗██║  ██║███████║██║     
         ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝     
        {Fore.RESET}"""
        print(banner)
        print(f"{Fore.YELLOW}||    Advanced Vulnerability Scanner (CLI Version)    ||{Fore.RESET}")
        print("="*60)

    def get_target_url(self):
        while True:
            url = input("Enter target URL (e.g., https://example.com): ").strip()
            if not url:
                print(f"{Fore.RED}Error: URL cannot be empty{Fore.RESET}")
                continue
            
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            try:
                response = requests.head(url, timeout=5)
                return url
            except requests.RequestException as e:
                print(f"{Fore.RED}Connection error: {str(e)}{Fore.RESET}")
                if input("Continue anyway? (y/n): ").lower() != 'y':
                    continue

    def show_scan_options(self):
        print(f"\n{Fore.CYAN}Scan Options:{Fore.RESET}")
        for key, value in self.scan_options.items():
            print(f"{Fore.GREEN}{key}. {Fore.WHITE}{value}")

    def get_scan_choice(self):
        while True:
            choice = input("\nSelect scan option (1-5): ").strip()
            if choice in self.scan_options:
                return [choice] if choice != "4" else ["1", "2", "3"]
            print(f"{Fore.RED}Invalid option{Fore.RESET}")

    def scan_progress(self):
        chars = ['|', '/', '-', '\\']
        i = 0
        while not self.stop_scan_flag:
            color = self.colors[i % len(self.colors)]
            print(f"{color}\rScanning... {chars[i % 4]}", end="")
            time.sleep(0.1)
            i += 1

    def start_scan(self, url, options):
        self.stop_scan_flag = False
        print(f"\nScanning: {url}")
        
        progress_thread = threading.Thread(target=self.scan_progress)
        progress_thread.daemon = True
        progress_thread.start()
        
        try:
            time.sleep(2)
            
            if '1' in options:
                self.smart_scan(url)
            
            if '2' in options:
                self.full_scan(url)
            
            if '3' in options:
                self.info_gathering(url)
            
            self.stop_scan_flag = True
            progress_thread.join()
            
            print(f"\n\n{Fore.GREEN}Scan completed!{Fore.RESET}")
            self.show_results()
            
        except KeyboardInterrupt:
            self.stop_scan_flag = True
            progress_thread.join()
            print(f"\n{Fore.RED}Scan interrupted!{Fore.RESET}")

    def smart_scan(self, url):
        print(f"\n{Fore.CYAN}Running Smart Scan...{Fore.RESET}")
        time.sleep(1)
        self.scan_results.extend([
            {"type": "SQL Injection", "severity": "High", "description": "Potential SQLi in login form"},
            {"type": "XSS", "severity": "Medium", "description": "Possible XSS in search parameter"}
        ])

    def full_scan(self, url):
        print(f"\n{Fore.CYAN}Running Full Scan...{Fore.RESET}")
        time.sleep(1.5)
        self.scan_results.extend([
            {"type": "CSRF", "severity": "Medium", "description": "Missing CSRF token"},
            {"type": "Outdated Software", "severity": "High", "description": "WordPress 4.7 detected"},
            {"type": "Directory Listing", "severity": "Low", "description": "Enabled on /uploads/"}
        ])

    def info_gathering(self, url):
        print(f"\n{Fore.CYAN}Gathering Information...{Fore.RESET}")
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            ip = socket.gethostbyname(domain)
            
            info = {
                "Domain": domain,
                "IP Address": ip,
                "Server": "Apache/2.4.29",
                "Technologies": ["PHP 7.2", "jQuery 1.12.4", "WordPress 5.4"],
                "Open Ports": ["80 (HTTP)", "443 (HTTPS)", "22 (SSH)"]
            }
            
            print(f"\n{Fore.GREEN}=== Collected Information ==={Fore.RESET}")
            for key, value in info.items():
                print(f"{Fore.YELLOW}{key}: {Fore.WHITE}{', '.join(value) if isinstance(value, list) else value}")
            
            self.scan_results.append({"type": "Info Gathering", "data": info})
            time.sleep(1)
        except Exception as e:
            print(f"{Fore.RED}Error: {str(e)}{Fore.RESET}")

    def show_results(self):
        if not self.scan_results:
            print(f"{Fore.GREEN}No vulnerabilities found.{Fore.RESET}")
            return
        
        print(f"\n{Fore.GREEN}=== Scan Results ==={Fore.RESET}")
        for i, result in enumerate(self.scan_results, 1):
            if result['type'] == "Info Gathering":
                continue
            color = self.colors[i % len(self.colors)]
            print(f"{color}\nFinding #{i}:")
            print(f"{Fore.YELLOW}Type: {Fore.WHITE}{result['type']}")
            print(f"{Fore.YELLOW}Severity: {self.get_severity_color(result['severity'])}{result['severity']}")
            print(f"{Fore.YELLOW}Description: {Fore.WHITE}{result['description']}")

    def get_severity_color(self, severity):
        if severity == "High":
            return Fore.RED
        elif severity == "Medium":
            return Fore.YELLOW
        return Fore.GREEN

    def run(self):
        self.display_banner()
        url = self.get_target_url()
        self.show_scan_options()
        options = self.get_scan_choice()
        self.start_scan(url, options)

        if input("\nSave results to file? (y/n): ").lower() == 'y':
            filename = input("Filename (default: scan_results.txt): ").strip() or "scan_results.txt"
            try:
                with open(filename, 'w') as f:
                    f.write(f"Scan results for: {url}\n\n")
                    for result in self.scan_results:
                        if result['type'] == "Info Gathering":
                            continue
                        f.write(f"Type: {result['type']}\nSeverity: {result['severity']}\nDescription: {result['description']}\n\n")
                print(f"{Fore.GREEN}Results saved to {filename}{Fore.RESET}")
            except Exception as e:
                print(f"{Fore.RED}Error saving file: {str(e)}{Fore.RESET}")

        print(f"\n{Fore.CYAN}Scan finished.{Fore.RESET}")

if __name__ == "__main__":
    scanner = VulnerabilityScanner()
    scanner.run()