import ipaddress
from typing import Optional


RESERVED_RANGES = {
    'Loopback': ('127.0.0.0', '127.255.255.255'),
    'Private (10.x)': ('10.0.0.0', '10.255.255.255'),
    'Private (172.x)': ('172.16.0.0', '172.31.255.255'),
    'Private (192.168.x)': ('192.168.0.0', '192.168.255.255'),
    'Link-Local': ('169.254.0.0', '169.254.255.255'),
    'Multicast': ('224.0.0.0', '239.255.255.255'),
    'Broadcast': ('255.255.255.255', '255.255.255.255'),
    'Unspecified': ('0.0.0.0', '0.0.0.0'),
    'Carrier-grade NAT': ('100.64.0.0', '100.127.255.255'),
    'Documentation (TEST-NET-1)': ('192.0.2.0', '192.0.2.255'),
    'Documentation (TEST-NET-2)': ('198.51.100.0', '198.51.100.255'),
    'Documentation (TEST-NET-3)': ('203.0.113.0', '203.0.113.255'),
}


def analyze_ip(ip_str: str) -> dict:
    findings = []
    recommendations = []
    risk_score = 0
    ip_str = ip_str.strip()

    try:
        ip_obj = ipaddress.ip_address(ip_str)
        is_valid = True
    except ValueError:
        is_valid = False
        return {
            'ip_address': ip_str,
            'is_valid': False,
            'is_public': False,
            'is_reserved': False,
            'ip_type': 'Invalid',
            'threat_level': 'Medium',
            'risk_score': 50,
            'findings': f'Invalid IP address format: {ip_str}',
            'recommendations': 'Provide a valid IPv4 or IPv6 address.',
        }

    is_public = ip_obj.is_global
    is_reserved = ip_obj.is_reserved
    is_private = ip_obj.is_private
    is_loopback = ip_obj.is_loopback
    is_link_local = ip_obj.is_link_local
    is_multicast = ip_obj.is_multicast

    ip_type = 'IPv6' if ip_obj.version == 6 else 'IPv4'

    if is_valid:
        findings.append(f'Valid {ip_type} address')

    if is_loopback:
        risk_score += 5
        findings.append('Loopback address (127.x.x.x) - local system traffic')
        recommendations.append('Loopback addresses are internal. No external threat.')
    elif is_private:
        risk_score += 10
        findings.append('Private/internal IP address (RFC 1918)')
        recommendations.append('Private IPs are not routable on the public internet. Verify internal source.')
    elif is_link_local:
        risk_score += 10
        findings.append('Link-local address (169.254.x.x)')
        recommendations.append('Link-local addresses are auto-assigned when DHCP fails.')
    elif is_reserved:
        risk_score += 15
        findings.append('Reserved IP address - not typically used for legitimate traffic')
        recommendations.append('Reserved addresses may indicate misconfiguration or testing.')
    elif is_multicast:
        findings.append('Multicast address - used for group communications')
    elif is_public:
        findings.append('Public IP address - routable on the internet')
        recommendations.append('Public IP detected. Consider checking with threat intelligence feeds for reputation.')

    if ip_obj.version == 6 and not ip_obj.is_loopback:
        findings.append('IPv6 address detected')
        if is_public:
            risk_score += 5
            recommendations.append('IPv6 public addresses may bypass some firewall rules. Ensure proper filtering.')

    known_malicious_prefixes = ['104.28', '185.220', '45.33.32']
    for prefix in known_malicious_prefixes:
        if ip_str.startswith(prefix):
            risk_score += 20
            findings.append(f'IP falls in a range sometimes associated with scanning activity')
            recommendations.append('Cross-reference with threat intelligence databases for confirmation.')
            break

    risk_score = min(risk_score, 100)

    if risk_score >= 50:
        threat_level = 'High'
    elif risk_score >= 30:
        threat_level = 'Medium'
    elif risk_score > 0:
        threat_level = 'Low'
    else:
        threat_level = 'Safe'

    if not recommendations:
        recommendations.append('IP analysis complete. Integrate with threat intelligence APIs for deeper analysis.')

    return {
        'ip_address': ip_str,
        'is_valid': is_valid,
        'is_public': is_public,
        'is_reserved': is_reserved or is_loopback or is_link_local or is_multicast,
        'ip_type': ip_type,
        'threat_level': threat_level,
        'risk_score': risk_score,
        'findings': '\n'.join(findings),
        'recommendations': '\n'.join(recommendations),
    }
