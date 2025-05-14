import argparse
import os
import requests
import time
import json
from pathlib import Path
from colorama import Fore, Style, init
from typing import Optional, Dict, Any

# Initialize colorama
init(autoreset=True)

class VirusTotalScanner:
    """A comprehensive VirusTotal scanning tool with support for IPs, URLs, and files."""

    MAX_FILE_SIZE = 32 * 1024 * 1024  # 32MB
    POLLING_ATTEMPTS = 12  # Max attempts for result polling
    POLLING_DELAY = 5  # Seconds between polling attempts

    def __init__(self, api_key: str):
        """Initialize the scanner with API key."""
        if not api_key or len(api_key) != 64:
            raise ValueError("Invalid VirusTotal API key format")

        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

    def scan_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Scan an IP address using VirusTotal API."""
        if not self._validate_ip(ip_address):
            print(f"{Fore.RED}Invalid IP address format: {ip_address}")
            return None

        url = f"{self.base_url}ip_addresses/{ip_address}"
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}Error scanning IP {ip_address}: {e}")
            return None

    def scan_url(self, url_to_scan: str) -> Optional[Dict[str, Any]]:
        """Scan a URL using VirusTotal API."""
        if not self._validate_url(url_to_scan):
            print(f"{Fore.RED}Invalid URL format: {url_to_scan}")
            return None

        submit_url = f"{self.base_url}urls"
        payload = {"url": url_to_scan}

        try:
            # Submit URL for scanning
            response = requests.post(submit_url, headers=self.headers, data=payload, timeout=10)
            response.raise_for_status()
            scan_id = response.json().get('data', {}).get('id')

            if not scan_id:
                print(f"{Fore.RED}Failed to get scan ID from response")
                return None

            # Poll for results
            return self._poll_analysis_results(scan_id, "URL")

        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}Error scanning URL {url_to_scan}: {e}")
            return None

    def scan_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Scan a file using VirusTotal API."""
        if not Path(file_path).exists():
            print(f"{Fore.RED}File not found: {file_path}")
            return None

        file_size = Path(file_path).stat().st_size
        if file_size > self.MAX_FILE_SIZE:
            print(f"{Fore.RED}File too large (max {self.MAX_FILE_SIZE/1024/1024}MB)")
            return None

        upload_url = f"{self.base_url}files"

        try:
            with open(file_path, 'rb') as file:
                files = {'file': (Path(file_path).name, file)}
                response = requests.post(upload_url, headers=self.headers, files=files, timeout=30)
                response.raise_for_status()
                analysis_id = response.json().get('data', {}).get('id')

                if not analysis_id:
                    print(f"{Fore.RED}Failed to get analysis ID from response")
                    return None

                # Poll for results
                return self._poll_analysis_results(analysis_id, "file")

        except Exception as e:
            print(f"{Fore.RED}Error scanning file {file_path}: {e}")
            return None

    def _poll_analysis_results(self, resource_id: str, resource_type: str) -> Optional[Dict[str, Any]]:
        """Poll VirusTotal for analysis results."""
        report_url = f"{self.base_url}analyses/{resource_id}"

        for attempt in range(self.POLLING_ATTEMPTS):
            try:
                report_response = requests.get(report_url, headers=self.headers, timeout=10)
                report_response.raise_for_status()
                result = report_response.json()

                status = result.get('data', {}).get('attributes', {}).get('status')

                if status == 'completed':
                    return result
                elif status == 'queued':
                    if attempt == 0:
                        print(f"{Fore.YELLOW}{resource_type} scan is queued. Waiting for results...")
                    time.sleep(self.POLLING_DELAY)
                else:
                    print(f"{Fore.RED}Unexpected status: {status}")
                    return None

            except requests.exceptions.RequestException as e:
                print(f"{Fore.RED}Error polling results (attempt {attempt + 1}): {e}")
                if attempt == self.POLLING_ATTEMPTS - 1:
                    return None
                time.sleep(self.POLLING_DELAY)

        print(f"{Fore.RED}Max polling attempts reached without completion")
        return None

    def print_results(self, result: Dict[str, Any], target: str) -> None:
        """Print formatted results from VirusTotal scan with colors."""
        if not result:
            print(f"{Fore.YELLOW}No results for {target}")
            return

        print(f"\n{Fore.CYAN}=== Results for {target} ===")

        if 'data' not in result or 'attributes' not in result['data']:
            print(f"{Fore.YELLOW}Unexpected result format")
            print(json.dumps(result, indent=2))
            return

        attributes = result['data']['attributes']
        stats = attributes.get('last_analysis_stats') or attributes.get('stats')

        if not stats:
            print(f"{Fore.YELLOW}No scan statistics found in results")
            return

        # Print detection stats
        print(f"\n{Fore.WHITE}Detection Stats:")
        print(f"  {Fore.RED}Malicious: {stats.get('malicious', 0)}")
        print(f"  {Fore.YELLOW}Suspicious: {stats.get('suspicious', 0)}")
        print(f"  {Fore.GREEN}Undetected: {stats.get('undetected', 0)}")
        print(f"  {Fore.CYAN}Harmless: {stats.get('harmless', 0)}")

        if 'timeout' in stats:
            print(f"  {Fore.BLUE}Timeout: {stats.get('timeout', 0)}")

        # Print detailed results
        analysis_results = attributes.get('last_analysis_results') or attributes.get('results')
        if analysis_results:
            print(f"\n{Fore.WHITE}Detailed Results:")
            for engine, details in analysis_results.items():
                category = details.get('category')
                if category != 'undetected':
                    color = Fore.WHITE
                    if category == 'malicious':
                        color = Fore.RED
                    elif category == 'suspicious':
                        color = Fore.YELLOW
                    print(f"  {color}{engine}: {details.get('result', 'N/A')} ({category})")

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        """Basic IP address validation."""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False

    @staticmethod
    def _validate_url(url: str) -> bool:
        """Basic URL validation."""
        return url.startswith(('http://', 'https://')) and '.' in url

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="VirusTotal Scanner CLI",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # Arguments
    parser.add_argument(
        "--api-key",
        help="Your VirusTotal API key (or set VT_API_KEY environment variable)",
        default=os.getenv('VT_API_KEY')
    )
    parser.add_argument("--ip", help="IP address to scan")
    parser.add_argument("--url", help="URL to scan")
    parser.add_argument("--file", help="File to scan")
    parser.add_argument(
        "--output",
        type=argparse.FileType('w'),
        help="Output file to save results (JSON format)"
    )

    args = parser.parse_args()

    if not args.api_key:
        parser.error("API key is required (--api-key or VT_API_KEY environment variable)")

    if not any([args.ip, args.url, args.file]):
        parser.error("No target specified. Please provide --ip, --url, or --file")

    try:
        scanner = VirusTotalScanner(args.api_key)
    except ValueError as e:
        print(f"{Fore.RED}Error: {e}")
        return

    result = None
    target = ""

    try:
        if args.ip:
            result = scanner.scan_ip(args.ip)
            target = f"IP {args.ip}"
        elif args.url:
            result = scanner.scan_url(args.url)
            target = f"URL {args.url}"
        elif args.file:
            result = scanner.scan_file(args.file)
            target = f"File {args.file}"

        if result:
            scanner.print_results(result, target)

            if args.output:
                json.dump(result, args.output, indent=2)
                print(f"\n{Fore.GREEN}Results saved to {args.output.name}")

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user")
    except Exception as e:
        print(f"{Fore.RED}Unexpected error: {e}")

if __name__ == "__main__":
    main()
