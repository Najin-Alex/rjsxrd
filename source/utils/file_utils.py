"""File handling utilities with refactored, streamlined logic."""

import os
import ipaddress
from typing import List, Set
import re
import base64
import json
from utils.logger import log
from config.settings import SNI_DOMAINS


def save_to_local_file(path: str, content: str):
    """Saves content to a local file."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as file:
        file.write(content)
    log(f"Data saved locally to {path}")


def load_from_local_file(path: str) -> str:
    """Loads content from a local file."""
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8") as file:
        return file.read()


def split_config_file(content: str, max_lines_per_file: int = 300) -> List[str]:
    """Splits a config file content into smaller parts."""
    lines = content.strip().split('\n')
    # Remove empty lines
    lines = [line.strip() for line in lines if line.strip()]

    chunks = []
    for i in range(0, len(lines), max_lines_per_file):
        chunk = '\n'.join(lines[i:i + max_lines_per_file])
        chunks.append(chunk)

    return chunks


def extract_host_port(line: str):
    """Extracts host and port from a config line."""
    if not line:
        return None
    if line.startswith("vmess://"):
        try:
            payload = line[8:]
            rem = len(payload) % 4
            if rem:
                payload += '=' * (4 - rem)
            decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
            if decoded.startswith('{'):
                j = json.loads(decoded)
                host = j.get('add') or j.get('host') or j.get('ip')
                port = j.get('port')
                if host and port:
                    return str(host), str(port)
        except Exception:
            pass
        return None
    m = re.search(r'(?:@|//)([\w\.-]+):(\d{1,5})', line)
    if m:
        return m.group(1), m.group(2)
    return None


def extract_ip_from_config(config_line: str):
    """Extract IP address from a config line."""
    if not config_line:
        return None

    # Extract host from config line
    host_port = extract_host_port(config_line)
    if host_port:
        host = host_port[0]
        # Check if it's an IP address
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            # Not an IP address, return None
            return None
    return None


def load_cidr_whitelist(cidr_file_path: str = "../source/config/cidrwhitelist.txt") -> set:
    """Load CIDR whitelist from file and return as a set of individual IPs for fast lookup."""
    try:
        with open(cidr_file_path, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip()]

        # Create a set of valid IP addresses for O(1) lookup
        ip_set = set()
        for line in lines:
            try:
                # Validate it's a valid IP and add to set
                ipaddress.ip_address(line)
                ip_set.add(line)
            except ValueError:
                # Skip invalid entries
                continue
        return ip_set
    except FileNotFoundError:
        log(f"CIDR whitelist file not found at {cidr_file_path}")
        return set()


def is_ip_in_cidr_whitelist(ip_str: str, cidr_whitelist: set) -> bool:
    """Check if an IP address is in the CIDR whitelist (optimized version with O(1) lookup)."""
    if not ip_str or not cidr_whitelist:
        return False

    # Direct lookup in the set (O(1) operation)
    return ip_str in cidr_whitelist


def deduplicate_configs(configs: List[str]) -> List[str]:
    """Deduplicates configs based on host:port combination."""
    seen_full = set()
    seen_hostport = set()
    unique_configs = []

    for cfg in configs:
        c = cfg.strip()
        if not c or c in seen_full:
            continue
        seen_full.add(c)

        hostport = extract_host_port(c)
        if hostport:
            key = f"{hostport[0].lower()}:{hostport[1]}"
            if key in seen_hostport:
                continue
            seen_hostport.add(key)
        unique_configs.append(c)

    return unique_configs


def has_insecure_setting(config_line: str) -> bool:
    """Check if a config has insecure settings."""
    config_lower = config_line.lower()

    # Check for allowInsecure in query parameters (common in vless/trojan)
    if 'allowinsecure=' in config_lower:
        # Check if it's set to true, 1, or yes
        allow_insecure_match = re.search(r'allowinsecure=([^&\?#]+)', config_lower)
        if allow_insecure_match:
            value = allow_insecure_match.group(1).strip()
            if value in ['1', 'true', 'yes', 'on']:
                return True

    # Check for insecure in query parameters
    if 'insecure=' in config_lower:
        insecure_match = re.search(r'insecure=([^&\?#]+)', config_lower)
        if insecure_match:
            value = insecure_match.group(1).strip()
            if value in ['1', 'true', 'yes', 'on']:
                return True

    # Check for skip-cert-verify in query parameters (used in some clients like TUIC)
    if 'skip-cert-verify=' in config_lower:
        skip_cert_verify_match = re.search(r'skip-cert-verify=([^&\?#]+)', config_lower)
        if skip_cert_verify_match:
            value = skip_cert_verify_match.group(1).strip()
            if value in ['1', 'true', 'yes', 'on', 'enabled']:
                return True

    # Check for security=none (no encryption)
    if 'security=none' in config_lower:
        return True

    # Check for encryption=none in VLESS configs (when not using TLS/REALITY)
    # Note: encryption=none with TLS/REALITY is acceptable, but we can't determine transport layer here
    # So we treat encryption=none alone as potentially insecure
    if 'encryption=none' in config_lower and ('security=tls' not in config_lower and 'security=reality' not in config_lower):
        return True

    # Check for insecure settings in vmess base64 JSON configuration
    if config_line.startswith("vmess://"):
        try:
            payload = config_line[8:]
            rem = len(payload) % 4
            if rem:
                payload += '=' * (4 - rem)
            decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
            if decoded.startswith('{'):
                j = json.loads(decoded)
                # Check for insecure settings in vmess config
                insecure_setting = j.get('insecure') or j.get('allowInsecure')
                if insecure_setting in [True, 'true', 1, '1']:
                    return True
                # Also check for security=none in vmess config
                security_setting = j.get('scy') or j.get('security')
                if security_setting and str(security_setting).lower() == 'none':
                    return True
                # Check for legacy VMess mode (alterId > 0 indicates vulnerable legacy mode)
                alter_id = j.get('aid') or j.get('alterId')
                if alter_id is not None:
                    alter_id_value = int(alter_id) if isinstance(alter_id, (int, str)) else 0
                    if alter_id_value > 0:
                        return True  # Legacy VMess mode with MD5 header authentication is insecure
        except Exception:
            pass

    # Check for insecure Shadowsocks methods
    if config_line.startswith("ss://"):
        try:
            # Parse the Shadowsocks URL to extract method
            # Format: ss://method:password@host:port
            # Or: ss://base64(method:password)@host:port
            ss_part = config_line[5:]  # Remove "ss://"

            # Check if the format is method:password@host:port (non-base64)
            if ':' in ss_part and '@' in ss_part and ss_part.index(':') < ss_part.index('@'):
                # Format is method:password@host:port
                method = ss_part.split(':')[0].lower()

                # Check for weak encryption methods
                weak_methods = [
                    'rc4-md5', 'rc4-md5-6', 'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
                    'aes-128-cfb8', 'aes-192-cfb8', 'aes-256-cfb8', 'aes-128-cfb1',
                    'aes-192-cfb1', 'aes-256-cfb1', 'aes-128-cfb-fast', 'aes-192-cfb-fast',
                    'aes-256-cfb-fast', 'aes-128-cfb-simple', 'aes-192-cfb-simple',
                    'aes-256-cfb-simple', 'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
                    'bf-cfb', 'camellia-128-cfb', 'camellia-192-cfb', 'camellia-256-cfb',
                    'cast5-cfb', 'des-cfb', 'idea-cfb', 'rc2-cfb', 'seed-cfb',
                    'salsa20', 'chacha20', 'xsalsa20', 'xchacha20'
                ]

                if method in weak_methods:
                    return True
            else:
                # Contains credentials in base64 format: ss://base64(method:password)@host:port
                if '@' in ss_part:
                    # Contains credentials, method is in base64 part before '@'
                    encoded_part = ss_part.split('@')[0]

                    # Handle padding for base64 decoding
                    rem = len(encoded_part) % 4
                    if rem:
                        padded_encoded_part = encoded_part + '=' * (4 - rem)
                    else:
                        padded_encoded_part = encoded_part

                    try:
                        decoded_credentials = base64.b64decode(padded_encoded_part).decode('utf-8')
                        method = decoded_credentials.split(':')[0].lower()

                        # Check for weak encryption methods
                        weak_methods = [
                            'rc4-md5', 'rc4-md5-6', 'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
                            'aes-128-cfb8', 'aes-192-cfb8', 'aes-256-cfb8', 'aes-128-cfb1',
                            'aes-192-cfb1', 'aes-256-cfb1', 'aes-128-cfb-fast', 'aes-192-cfb-fast',
                            'aes-256-cfb-fast', 'aes-128-cfb-simple', 'aes-192-cfb-simple',
                            'aes-256-cfb-simple', 'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
                            'bf-cfb', 'camellia-128-cfb', 'camellia-192-cfb', 'camellia-256-cfb',
                            'cast5-cfb', 'des-cfb', 'idea-cfb', 'rc2-cfb', 'seed-cfb',
                            'salsa20', 'chacha20', 'xsalsa20', 'xchacha20'
                        ]

                        if method in weak_methods:
                            return True

                    except Exception:
                        # If we can't decode, continue with other checks
                        pass
        except Exception:
            pass

    # Check for insecure ShadowsocksR methods
    if config_line.startswith("ssr://"):
        try:
            # SSR URL format: ssr://base64(host:port:protocol:method:obfs:base64pass/?params)
            payload = config_line[6:]
            rem = len(payload) % 4
            if rem:
                payload += '=' * (4 - rem)
            decoded = base64.b64decode(payload).decode('utf-8')

            # Parse the decoded string: host:port:protocol:method:obfs:base64(password)
            parts = decoded.split(':')
            if len(parts) >= 6:
                method = parts[3].lower()

                # Check for weak encryption methods
                weak_methods = [
                    'rc4-md5', 'rc4-md5-6', 'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
                    'aes-128-cfb8', 'aes-192-cfb8', 'aes-256-cfb8', 'aes-128-cfb1',
                    'aes-192-cfb1', 'aes-256-cfb1', 'aes-128-cfb-fast', 'aes-192-cfb-fast',
                    'aes-256-cfb-fast', 'aes-128-cfb-simple', 'aes-192-cfb-simple',
                    'aes-256-cfb-simple', 'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
                    'bf-cfb', 'camellia-128-cfb', 'camellia-192-cfb', 'camellia-256-cfb',
                    'cast5-cfb', 'des-cfb', 'idea-cfb', 'rc2-cfb', 'seed-cfb',
                    'salsa20', 'chacha20', 'xsalsa20', 'xchacha20'
                ]

                if method in weak_methods:
                    return True
        except Exception:
            pass

    # Check for other insecure indicators in the URL
    if 'insecure=1' in config_lower or 'insecure=true' in config_lower:
        return True
    if 'verify=0' in config_lower or 'verify=false' in config_lower:
        return True

    return False


def filter_secure_configs(configs: List[str]) -> List[str]:
    """Filter out configs with insecure settings."""
    secure_configs = []
    for config in configs:
        if not has_insecure_setting(config):
            secure_configs.append(config)
    return secure_configs


def prepare_config_content(content: str) -> List[str]:
    """Prepares and normalizes config content by separating glued configs."""
    # Add newlines before known protocol prefixes that might be glued to previous lines
    content = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2|hy2)://', r'\n\1://', content)
    lines = content.splitlines()
    # Filter out empty lines, comments, and non-VPN config lines
    configs = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#') and is_valid_vpn_config_url(line):
            configs.append(line)
    return configs


def is_valid_vpn_config_url(line: str) -> bool:
    """Check if a line is a valid VPN config URL by verifying it starts with a known protocol followed by ://"""
    line = line.strip()
    # Check if the line starts with one of the known VPN protocols followed by ://
    return bool(re.match(r'^(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2|hy2)://', line, re.IGNORECASE))


def apply_sni_cidr_filter(configs: List[str], filter_secure: bool = True) -> List[str]:
    """Apply SNI/CIDR filtering to configs, with optional secure filtering."""
    from config.settings import SNI_DOMAINS
    from utils.file_utils import load_cidr_whitelist, is_ip_in_cidr_whitelist, extract_ip_from_config

    # Load CIDR whitelist
    cidr_whitelist = load_cidr_whitelist()

    # Optimize domain list by removing redundant domains
    sorted_domains = sorted(SNI_DOMAINS, key=len)
    optimized_domains = []

    for d in sorted_domains:
        is_redundant = False
        for existing in optimized_domains:
            if existing in d:
                is_redundant = True
                break
        if not is_redundant:
            optimized_domains.append(d)

    # Compile Regex
    try:
        pattern_str = r"(?:" + "|".join(re.escape(d) for d in optimized_domains) + r")"
        sni_regex = re.compile(pattern_str)
    except Exception as e:
        log(f"Error compiling Regex: {e}")
        return []

    filtered_configs = []
    for config in configs:
        config = config.strip()
        if not config:
            continue

        # Check if config should be included based on SNI or CIDR criteria
        matches_sni = sni_regex.search(config)
        matches_cidr = False
        if cidr_whitelist:
            ip = extract_ip_from_config(config)
            if ip and is_ip_in_cidr_whitelist(ip, cidr_whitelist):
                matches_cidr = True

        # If config matches either SNI or CIDR criteria
        if matches_sni or matches_cidr:
            # Only add the config if it's a valid VPN config URL
            if is_valid_vpn_config_url(config):
                # Apply security filter based on the parameter
                if not filter_secure or not has_insecure_setting(config):
                    filtered_configs.append(config)

    return filtered_configs