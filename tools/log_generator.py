#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
방화벽 세션 로그 생성기
-----------------------
실제 인터넷 트래픽과 유사한 패턴을 가진 Juniper 방화벽 세션 로그를 생성합니다.
랜덤하게 IP와 포트를 사용하여 트래픽을 시뮬레이션하되, 실제 인터넷 트래픽과
유사한 비율로 생성합니다.

주요 특징:
- 목적지 IP와 포트에 대한 쏠림 현상 구현 (파레토 분포)
- 소수의 well-known 포트로 집중되는 트래픽 패턴
- 소수의 인기 있는 목적지 IP로 집중되는 트래픽 패턴
- 실제 주니퍼 방화벽 로그 포맷 준수
"""

import random
import ipaddress
import datetime
import argparse
import os
import time
import sys
import socket
import logging
import logging.handlers
import numpy as np
from collections import defaultdict

# 상수 정의
# 일반적인 인터넷 트래픽 분포를 반영한 프로토콜 분포
PROTOCOL_DISTRIBUTION = {
    'tcp': 80,    # TCP 80%
    'udp': 15,    # UDP 15%
    'icmp': 4,    # ICMP 4%
    'icmpv6': 1   # ICMPv6 1%
}

# 프로토콜 번호 매핑
PROTOCOL_NUMBER_MAP = {
    'tcp': 6,
    'udp': 17,
    'icmp': 1,
    'icmpv6': 58
}

# 일반적인 인터넷 트래픽 포트 분포 - 쏠림 현상을 더 강화
PORT_DISTRIBUTION = {
    # 웹 관련 (HTTP, HTTPS) - 비중 증가
    80: 25,    # 25% - 웹 트래픽 증가
    443: 35,   # 35% - HTTPS 트래픽이 대부분
    8080: 3,
    8443: 2,
    
    # 이메일 관련
    25: 3,
    465: 2, 
    587: 2,
    110: 1,
    143: 1,
    993: 1,
    
    # DNS
    53: 12,   # DNS 트래픽 증가
    
    # 원격 접속
    22: 4,    # SSH
    3389: 2,  # RDP
    
    # 데이터베이스
    1433: 1,  # MSSQL
    3306: 1,  # MySQL
    5432: 1,  # PostgreSQL
    
    # 기타 일반적인 서비스
    21: 1,    # FTP
    123: 1,   # NTP
    161: 0.5, # SNMP
    
    # 랜덤 포트 (클라이언트 에페머럴 포트) - 나머지는 랜덤 포트로 할당
}

# IPv4/IPv6 비율
IPV4_PERCENTAGE = 85  # IPv4 85%, IPv6 15%

# 트래픽 방향성 (인바운드/아웃바운드)
DIRECTION_DISTRIBUTION = {
    'inbound': 40,   # 외부에서 들어오는 트래픽
    'outbound': 60   # 내부에서 나가는 트래픽
}

# 영역 정의
ZONE_PAIRS = [
    ('Trust', 'Untrust'),     # 내부->외부
    ('Untrust', 'Trust'),     # 외부->내부
    ('Trust', 'DMZ'),         # 내부->DMZ
    ('DMZ', 'Trust'),         # DMZ->내부
    ('Untrust', 'DMZ'),       # 외부->DMZ
    ('DMZ', 'Untrust')        # DMZ->외부
]

# 영역 쌍 가중치 (실제 트래픽 분포 반영)
ZONE_WEIGHTS = {
    ('Trust', 'Untrust'): 40,     # 내부->외부 (가장 많음)
    ('Untrust', 'Trust'): 30,     # 외부->내부
    ('Trust', 'DMZ'): 10,         # 내부->DMZ
    ('DMZ', 'Trust'): 10,         # DMZ->내부
    ('Untrust', 'DMZ'): 5,        # 외부->DMZ
    ('DMZ', 'Untrust'): 5         # DMZ->외부
}

# 내부 네트워크 서브넷 정의
INTERNAL_SUBNETS = [
    '10.1.0.0/16',    # 사내 업무용 네트워크
    '10.2.0.0/16',    # 사내 업무용 네트워크 2
    '172.16.0.0/12',  # 개발/테스트 네트워크
    '192.168.0.0/16'  # 소규모 지사 네트워크
]

# DMZ 서브넷 정의
DMZ_SUBNETS = [
    '203.0.113.0/24',   # 웹서버
    '198.51.100.0/24'   # 메일서버, DNS 등
]

# IPv6 서브넷 정의
IPV6_INTERNAL_SUBNETS = [
    '2001:db8:1::/48',
    '2001:db8:2::/48'
]

IPV6_DMZ_SUBNETS = [
    '2001:db8:3::/48'
]

# 외부 IP 주소 풀 - 상위 인기 있는 서비스 정의 (파레토 분포를 위한 리스트)
TOP_EXTERNAL_IPS = [
    '142.250.0.0/15',   # Google - 더 넓은 범위 할당
    '157.240.0.0/16',   # Facebook
    '52.0.0.0/11',      # AWS East
    '35.180.0.0/15',    # AWS Europe
    '104.16.0.0/12',    # Cloudflare
    '23.32.0.0/12',     # Akamai
    '8.8.8.8',          # Google DNS - 단일 IP로 높은 트래픽
    '1.1.1.1',          # Cloudflare DNS - 단일 IP로 높은 트래픽
]

# 외부 IP 주소 풀 (랜덤 IP와 함께 자주 접속하는 특정 외부 IP도 포함)
COMMON_EXTERNAL_IPS = [
    '8.8.4.4',          # Google DNS 보조
    '208.67.222.222',   # OpenDNS
    '208.67.220.220',   # OpenDNS 보조
    '31.13.0.0/16',     # Facebook 보조
    '199.232.0.0/16',   # Fastly CDN
    '108.177.0.0/16',   # Google 추가 범위
    '13.32.0.0/15',     # Amazon CloudFront
    '172.217.0.0/16',   # Google 추가 범위
    '151.101.0.0/16',   # Fastly CDN
    '198.41.128.0/17',  # Cloudflare 추가 범위
]

TOP_EXTERNAL_IPV6 = [
    '2606:4700::/32',   # Cloudflare
    '2620:0:2d0::/44',  # Google
    '2a03:2880::/32',   # Facebook
]

COMMON_EXTERNAL_IPV6 = [
    '2600:1f00::/24',   # AWS
    '2607:f8b0::/32',   # Google
    '2620:107:300f::/48', # Cloudflare DNS (1.1.1.1)
    '2001:4860:4860::/48', # Google DNS (8.8.8.8)
]

# 인터페이스 목록
INTERFACES = ['reth0.0', 'reth1.0', 'reth2.0', 'ge-0/0/0.0', 'ge-0/0/1.0']

# 종료 이유 목록 - 실제 로그 패턴에 맞게 업데이트
CLOSE_REASONS = [
    "TCP FIN",
    "TCP RST",
    "TCP SERVER RST",
    "idle Timeout",
    "response received",
    "policy deny",
    "session timeout",
    "resource manager",
    "ALG"
]

# 정책 이름 목록 - 실제 로그 패턴에 맞게 업데이트
POLICY_NAMES = [
    "None",
    "junos-dns-udp",
    "junos-http",
    "junos-https",
    "icmp",
    "junos-ssh",
    "junos-ftp",
    "junos-telnet",
    "junos-smtp",
    "permit-any"
]

# 세션 로그 템플릿 - 실제 주니퍼 로그 포맷에 맞게 업데이트
SESSION_LOG_TEMPLATE = """{timestamp} {hostname} RT_FLOW: RT_FLOW_SESSION_{action}: {close_reason}{src_ip}/{src_port}->{dst_ip}/{dst_port} 0x0 {policy_name} {src_ip}/{src_port}->{dst_ip}/{dst_port} 0x0 N/A N/A N/A N/A {protocol_num} {session_id} {src_zone} {dst_zone} {policy_id} {packets_in} {packets_out} {byte_count} UNKNOWN UNKNOWN N/A(N/A) {interface} UNKNOWN N/A N/A -1 N/A NA 0 0.0.0.0/0->0.0.0.0/0 NA NA N/A N/A Off root 0 N/A N/A"""

def generate_policy_name(protocol='tcp', dst_port=80):
    """
    정책 이름 생성 - 프로토콜과 포트에 기반하여 실제 같은 정책 이름 생성
    
    Args:
        protocol: 프로토콜
        dst_port: 목적지 포트
        
    Returns:
        str: 정책 이름
    """
    # 특정 포트와 프로토콜 조합에 기반한 정책 이름 생성
    if protocol == 'udp' and dst_port == 53:
        return "junos-dns-udp"
    elif protocol == 'tcp' and dst_port == 80:
        return "junos-http"
    elif protocol == 'tcp' and dst_port == 443:
        return "junos-https"
    elif protocol == 'tcp' and dst_port == 22:
        return "junos-ssh"
    elif protocol == 'tcp' and dst_port == 21:
        return "junos-ftp"
    elif protocol == 'tcp' and dst_port == 25:
        return "junos-smtp"
    elif protocol == 'icmp' or protocol == 'icmpv6':
        return "icmp"
    else:
        # 대부분은 None으로 설정
        return random.choice(["None"] * 8 + ["permit-any"] * 2)  # 80% None, 20% permit-any

# 전역 변수
heavy_hitter_percentage = 0.80
heavy_hitter_connection_count = 50

def weighted_choice(choices):
    """
    가중치가 적용된 선택
    
    Args:
        choices (dict): 선택지와 가중치 쌍
        
    Returns:
        선택된 항목
    """
    total = sum(choices.values())
    r = random.uniform(0, total)
    upto = 0
    for choice, weight in choices.items():
        upto += weight
        if upto > r:
            return choice
    # 만약 반올림 오류로 여기까지 오면 마지막 항목 반환
    return list(choices.keys())[-1]

def generate_random_ip(subnets):
    """
    주어진 서브넷 목록에서 랜덤 IP 주소 생성
    
    Args:
        subnets (list): IP 서브넷 문자열 목록
        
    Returns:
        str: 랜덤 IP 주소
    """
    subnet = random.choice(subnets)
    network = ipaddress.ip_network(subnet)
    
    # 서브넷 내에서 랜덤 IP 생성
    address_count = network.num_addresses
    if address_count > 1:
        host_bits = network.max_prefixlen - network.prefixlen
        if host_bits > 24:  # 너무 큰 서브넷은 제한
            host_bits = 24
        random_host = random.randrange(0, min(2**host_bits, 1000))
        ip = network[random_host]
    else:
        ip = network[0]
    
    return str(ip)

def generate_external_ip(is_ipv6=False):
    """
    외부 IP 주소 생성 (자주 사용되는 서비스 IP 또는 랜덤 공용 IP)
    파레토 분포를 사용하여 인기 있는 IP에 쏠림 현상 구현
    
    Args:
        is_ipv6 (bool): IPv6 여부
        
    Returns:
        str: IP 주소
    """
    # 파레토 분포 또는 zipf 분포 결정 (소수의 인기 사이트로 쏠림 현상)
    if is_ipv6:
        # IPv6 대상 IP 선택 로직
        # 90%는 인기 있는 서비스 IP로 집중, 10%는 랜덤 IP
        if random.random() < 0.65:  # 상위 인기 서비스 (65%)
            subnet = random.choice(TOP_EXTERNAL_IPV6)
            network = ipaddress.ip_network(subnet)
            host_bits = network.max_prefixlen - network.prefixlen
            if host_bits > 24:  # 너무 큰 서브넷은 제한
                host_bits = 24
            random_host = random.randrange(0, min(2**host_bits, 1000))
            return str(network[random_host])
        elif random.random() < 0.90:  # 일반적 서비스 (25%)
            subnet = random.choice(COMMON_EXTERNAL_IPV6)
            network = ipaddress.ip_network(subnet)
            host_bits = network.max_prefixlen - network.prefixlen
            if host_bits > 24:  # 너무 큰 서브넷은 제한
                host_bits = 24
            random_host = random.randrange(0, min(2**host_bits, 1000))
            return str(network[random_host])
        else:  # 랜덤 공용 IPv6 (10%)
            return str(ipaddress.IPv6Address(random.randrange(
                int(ipaddress.IPv6Address('2000::')),
                int(ipaddress.IPv6Address('3000::'))
            )))
    else:
        # IPv4 대상 IP 선택 로직 - 파레토 분포 적용
        rand_val = random.random()
        
        if rand_val < 0.65:  # 상위 인기 서비스 (65%)
            subnet_str = random.choices(TOP_EXTERNAL_IPS, k=1)[0]
            try:
                network = ipaddress.ip_network(subnet_str)
                host_bits = network.max_prefixlen - network.prefixlen
                if host_bits > 16:  # 너무 큰 서브넷은 제한
                    host_bits = 16
                random_host = random.randrange(0, min(2**host_bits, 1000))
                return str(network[random_host])
            except:
                # 단일 IP인 경우
                return subnet_str
        elif rand_val < 0.90:  # 일반적 서비스 (25%)
            subnet_str = random.choice(COMMON_EXTERNAL_IPS)
            try:
                network = ipaddress.ip_network(subnet_str)
                host_bits = network.max_prefixlen - network.prefixlen
                if host_bits > 16:  # 너무 큰 서브넷은 제한
                    host_bits = 16
                random_host = random.randrange(0, min(2**host_bits, 1000))
                return str(network[random_host])
            except:
                # 단일 IP인 경우
                return subnet_str
        else:  # 랜덤 공용 IPv4 (10%)
            while True:
                ip = str(ipaddress.IPv4Address(random.randrange(
                    int(ipaddress.IPv4Address('1.0.0.0')),
                    int(ipaddress.IPv4Address('223.255.255.255'))
                )))
                # 사설 IP 범위 제외
                if not (ip.startswith('10.') or 
                        ip.startswith('172.16.') or 
                        ip.startswith('172.17.') or 
                        ip.startswith('172.18.') or 
                        ip.startswith('172.19.') or 
                        ip.startswith('172.2') or 
                        ip.startswith('172.3') or 
                        ip.startswith('192.168.')):
                    return ip

def generate_port(dst=False, protocol='tcp'):
    """
    포트 번호 생성 - 목적지 포트에 쏠림 현상 적용
    
    Args:
        dst (bool): 목적지 포트 여부
        protocol (str): 프로토콜
    
    Returns:
        int: 포트 번호
    """
    if protocol in ['icmp', 'icmpv6']:
        return 0
    
    if dst:
        # 목적지 포트는 주로 서비스 포트 - 인기 포트로 쏠림 현상 강화
        rand_val = random.random()
        
        if rand_val < 0.92:  # 92%는 잘 알려진 포트로 집중
            # 파레토 분포와 유사한 방식으로 인기 포트를 더 자주 선택
            return weighted_choice(PORT_DISTRIBUTION)
        else:
            # 나머지 8%는 랜덤 포트 사용
            return random.randint(1024, 65535)
    else:
        # 소스 포트는 주로 임시(ephemeral) 포트
        if random.random() < 0.95:  # 95%는 임시 포트
            return random.randint(49152, 65535)
        else:
            # 5%는 잘 알려진 소스 포트 (서버-서버 통신 등)
            return weighted_choice(PORT_DISTRIBUTION)

def generate_session_id():
    """
    현실적인 세션 ID 생성
    
    Returns:
        int: 세션 ID
    """
    return random.randint(1000000, 9999999)

def generate_policy_id():
    """
    정책 ID 생성
    
    Returns:
        int: 정책 ID
    """
    return random.randint(100000000, 999999999)

def generate_packet_byte_info():
    """
    패킷 및 바이트 정보 생성
    
    Returns:
        tuple: (packets_in, packets_out, byte_count) 형태의 정보
    """
    # 패킷 수 생성 (입력/출력)
    packets_in_count = random.randint(1, 100)
    packets_in_bytes = random.randint(40, 1500) * packets_in_count
    packets_in = f"{packets_in_count}({packets_in_bytes})"
    
    packets_out_count = random.randint(1, 100)
    packets_out_bytes = random.randint(40, 1500) * packets_out_count
    packets_out = f"{packets_out_count}({packets_out_bytes})"
    
    # 전체 바이트 수
    byte_count = packets_in_count + packets_out_count
    
    return packets_in, packets_out, byte_count

def generate_session_log(session_id=None, timestamp=None, is_ipv6=False):
    """
    세션 로그 한 줄 생성 - 다양한 실제 패턴 지원
    
    Args:
        session_id (int): 세션 ID (None이면 자동 생성)
        timestamp (datetime): 타임스탬프 (기본값: 현재 시간)
        is_ipv6 (bool): IPv6 세션 여부
        
    Returns:
        str: 생성된 세션 로그
    """
    if timestamp is None:
        timestamp = datetime.datetime.now()
    
    if session_id is None:
        session_id = generate_session_id()
    
    # 타임스탬프 포맷 (Mar 17 22:30:45)
    formatted_timestamp = timestamp.strftime("%b %d %H:%M:%S")
    
    # 호스트명
    hostname = "O_FW_1"
    
    # 무작위 액션 (CREATE 또는 CLOSE)
    action = random.choice(["CREATE", "CLOSE"])
    
    # 종료 사유 - CLOSE 인 경우에만 설정
    close_reason = ""
    if action == "CLOSE":
        close_reason = f"session closed {random.choice(CLOSE_REASONS)}: "
    
    # 인터페이스 선택
    interface = random.choice(INTERFACES)
    
    # 정책 ID 생성
    policy_id = generate_policy_id()
    
    # 프로토콜 선택
    protocol = weighted_choice(PROTOCOL_DISTRIBUTION)
    if is_ipv6 and protocol == 'icmp':
        protocol = 'icmpv6'
    
    # 프로토콜 번호 매핑
    protocol_num = PROTOCOL_NUMBER_MAP[protocol]
    
    # 영역 쌍 선택
    zone_pair = weighted_choice(ZONE_WEIGHTS)
    src_zone, dst_zone = zone_pair
    
    # V1 접두사 추가 (실제 로그에 맞춤)
    src_zone = f"V1-{src_zone}"
    dst_zone = f"V1-{dst_zone}"
    
    # 방향 결정 (인바운드/아웃바운드)
    direction = weighted_choice(DIRECTION_DISTRIBUTION)
    
    # IP 주소 및 포트 생성
    if direction == 'outbound':
        # 아웃바운드 트래픽 (내부 -> 외부)
        if src_zone.endswith('Trust'):
            if is_ipv6:
                src_ip = generate_random_ip(IPV6_INTERNAL_SUBNETS)
            else:
                src_ip = generate_random_ip(INTERNAL_SUBNETS)
        else:  # DMZ
            if is_ipv6:
                src_ip = generate_random_ip(IPV6_DMZ_SUBNETS)
            else:
                src_ip = generate_random_ip(DMZ_SUBNETS)
        
        dst_ip = generate_external_ip(is_ipv6)
    else:
        # 인바운드 트래픽 (외부 -> 내부/DMZ)
        src_ip = generate_external_ip(is_ipv6)
        
        if dst_zone.endswith('Trust'):
            if is_ipv6:
                dst_ip = generate_random_ip(IPV6_INTERNAL_SUBNETS)
            else:
                dst_ip = generate_random_ip(INTERNAL_SUBNETS)
        else:  # DMZ
            if is_ipv6:
                dst_ip = generate_random_ip(IPV6_DMZ_SUBNETS)
            else:
                dst_ip = generate_random_ip(DMZ_SUBNETS)
    
    # 포트 생성
    src_port = generate_port(dst=False, protocol=protocol)
    dst_port = generate_port(dst=True, protocol=protocol)
    
    # 패킷 및 바이트 정보 생성 - 더 현실적인 값 사용
    packets_in_count = random.randint(1, 100)
    packets_in_bytes = random.randint(40, 1500) * packets_in_count
    packets_in = f"{packets_in_count}({packets_in_bytes})"
    
    packets_out_count = random.randint(1, 100)
    packets_out_bytes = random.randint(40, 1500) * packets_out_count
    packets_out = f"{packets_out_count}({packets_out_bytes})"
    
    # 전체 바이트 수
    byte_count = random.randint(1, 100)  # 실제 로그에서는 바이트 수가 패킷 수의 합과 다름
    
    # 정책 이름 생성 - 프로토콜과 포트에 맞는 현실적인 이름
    policy_name = generate_policy_name(protocol, dst_port)
    
    # 세션 로그 생성
    log = SESSION_LOG_TEMPLATE.format(
        timestamp=formatted_timestamp,
        hostname=hostname,
        action=action,
        close_reason=close_reason,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol_num=protocol_num,
        session_id=session_id,
        src_zone=src_zone,
        dst_zone=dst_zone,
        policy_id=policy_id,
        policy_name=policy_name,
        interface=interface,
        packets_in=packets_in,
        packets_out=packets_out,
        byte_count=byte_count
    )
    
    return log.strip()

def generate_connection_heavy_hitters(count=10, is_ipv6=False):
    """
    트래픽 쏠림 현상을 위한 상위 연결 정보 생성
    (소수의 IP/PORT 조합이 대다수 트래픽을 차지)
    
    Args:
        count (int): 생성할 연결 쌍 수
        is_ipv6 (bool): IPv6 사용 여부
        
    Returns:
        list: [(src_ip, dst_ip, dst_port)] 형태의 연결 목록
    """
    connections = []
    
    # 인기 트래픽 패턴 생성
    for _ in range(count):
        # 소스 IP (내부 네트워크에서)
        if is_ipv6:
            src_ip = generate_random_ip(IPV6_INTERNAL_SUBNETS)
        else:
            src_ip = generate_random_ip(INTERNAL_SUBNETS)
        
        # 대상 IP (주로 인기 있는 서비스)
        if is_ipv6:
            dst_ip = generate_external_ip(is_ipv6=True)
        else:
            # 확실히 인기 서비스에서 선택
            subnet_str = random.choices(TOP_EXTERNAL_IPS, k=1)[0]
            try:
                network = ipaddress.ip_network(subnet_str)
                host_bits = network.max_prefixlen - network.prefixlen
                if host_bits > 16:
                    host_bits = 16
                random_host = random.randrange(0, min(2**host_bits, 1000))
                dst_ip = str(network[random_host])
            except:
                # 단일 IP인 경우
                dst_ip = subnet_str
        
        # 대상 포트 (주로 인기 포트)
        protocol = 'tcp' if random.random() < 0.8 else 'udp'
        if protocol == 'tcp':
            # 웹 트래픽 위주로
            dst_port = random.choices([80, 443], weights=[30, 70], k=1)[0]
        else:
            # DNS 트래픽 위주로
            dst_port = 53
        
        connections.append((src_ip, dst_ip, dst_port, protocol))
    
    return connections

def generate_realistic_traffic_patterns(num_logs):
    """
    현실적인 트래픽 패턴을 가진 세션 로그들 생성
    
    Args:
        num_logs (int): 생성할 로그 수
        
    Returns:
        list: 생성된 세션 로그 목록
    """
    logs = []
    base_time = datetime.datetime.now() - datetime.timedelta(hours=24)
    
    # 파레토 분포 설정 - 소수의 연결이 대다수 트래픽 차지
    # 80:20 법칙 - 20%의 연결이 80%의 트래픽을 생성
    heavy_hitter_percentage = 0.80  # 80%의 트래픽은 소수의 연결에서 발생
    heavy_hitter_connection_count = 50  # 50개의 연결이 80%의 트래픽을 생성
    
    # 핵심 연결 쌍 생성 (자주 사용되는 소스IP-목적지IP-목적지포트 조합)
    heavy_hitter_connections = generate_connection_heavy_hitters(
        count=heavy_hitter_connection_count,
        is_ipv6=False
    )
    
    # IPv6 연결 쌍도 생성
    ipv6_heavy_hitter_connections = generate_connection_heavy_hitters(
        count=int(heavy_hitter_connection_count * 0.2),  # IPv6 비율 적용
        is_ipv6=True
    )
    
    # 반복 트래픽 패턴을 위한 세션 그룹 정의
    session_groups = []
    
    # 1. 인기 웹 서비스 트래픽 (내부->외부, HTTP/HTTPS) - 쏠림 현상 강화
    web_session = {
        'count': int(num_logs * 0.4),  # 전체 트래픽의 40%로 증가
        'src_zone': 'Trust',
        'dst_zone': 'Untrust',
        'protocols': ['tcp'],
        'ports': [80, 443],
        'src_ips': [],
        'dst_ips': [],
        'is_ipv6': False
    }
    
    # 내부 IP 30개 생성 (웹 서핑 사용자)
    for _ in range(30):
        web_session['src_ips'].append(generate_random_ip(INTERNAL_SUBNETS))
    
    # 외부 웹 서버 IP - 상위 인기 사이트에 집중
    for _ in range(20):  # 인기 사이트 수 감소 (집중도 강화)
        subnet_str = random.choice(TOP_EXTERNAL_IPS)
        try:
            network = ipaddress.ip_network(subnet_str)
            host_bits = network.max_prefixlen - network.prefixlen
            if host_bits > 16:
                host_bits = 16
            random_host = random.randrange(0, min(2**host_bits, 1000))
            web_session['dst_ips'].append(str(network[random_host]))
        except:
            # 단일 IP인 경우
            web_session['dst_ips'].append(subnet_str)
    
    session_groups.append(web_session)
    
    # 2. DNS 질의 패턴 (내부->외부, UDP/53)
    dns_session = {
        'count': int(num_logs * 0.15),  # 전체 트래픽의 15%
        'src_zone': 'Trust',
        'dst_zone': 'Untrust',
        'protocols': ['udp'],
        'ports': [53],
        'src_ips': [],
        'dst_ips': ['8.8.8.8', '8.8.4.4', '1.1.1.1', '208.67.222.222'],  # 일반적인 DNS 서버
        'is_ipv6': False
    }
    
    # 내부 IP 40개 생성 (DNS 클라이언트)
    for _ in range(40):
        dns_session['src_ips'].append(generate_random_ip(INTERNAL_SUBNETS))
    
    session_groups.append(dns_session)
    
    # 3. 이메일 트래픽 패턴 (DMZ->외부, 외부->DMZ, SMTP/IMAP/POP3)
    email_session = {
        'count': int(num_logs * 0.1),  # 전체 트래픽의 10%
        'src_zone': 'DMZ',
        'dst_zone': 'Untrust',
        'protocols': ['tcp'],
        'ports': [25, 465, 587, 110, 143, 993],
        'src_ips': [],
        'dst_ips': [],
        'is_ipv6': False
    }
    
    # DMZ 메일서버 IP 3개 생성
    for _ in range(3):
        email_session['src_ips'].append(generate_random_ip(DMZ_SUBNETS))
    
    # 외부 메일서버 IP 20개 생성
    for _ in range(20):
        email_session['dst_ips'].append(generate_external_ip())
    
    session_groups.append(email_session)
    
    # 4. 인바운드 웹 트래픽 (외부->DMZ, HTTP/HTTPS)
    inbound_web_session = {
        'count': int(num_logs * 0.2),  # 전체 트래픽의 20%
        'src_zone': 'Untrust',
        'dst_zone': 'DMZ',
        'protocols': ['tcp'],
        'ports': [80, 443],
        'src_ips': [],
        'dst_ips': [],
        'is_ipv6': False
    }
    
    # 외부 클라이언트 IP - 분포 적용
    # 일부 IP 대역에서 집중적으로 트래픽 발생
    for _ in range(50):  # 특정 국가/지역에서 집중
        inbound_web_session['src_ips'].append(generate_external_ip())
    
    # DMZ 웹서버 IP - 소수의 웹서버로 집중
    for _ in range(3):  # DMZ 웹서버 수 감소 (집중도 강화)
        inbound_web_session['dst_ips'].append(generate_random_ip(DMZ_SUBNETS))
    
    session_groups.append(inbound_web_session)
    
    # 5. DB 접속 트래픽 (내부->DMZ, TCP/DB 포트)
    db_session = {
        'count': int(num_logs * 0.08),  # 전체 트래픽의 8%
        'src_zone': 'Trust',
        'dst_zone': 'DMZ',
        'protocols': ['tcp'],
        'ports': [1433, 3306, 5432],
        'src_ips': [],
        'dst_ips': [],
        'is_ipv6': False
    }
    
    # 내부 클라이언트 IP 25개 생성
    for _ in range(25):
        db_session['src_ips'].append(generate_random_ip(INTERNAL_SUBNETS))
    
    # DMZ DB 서버 IP - 소수의 DB 서버로 집중 (2개)
    for _ in range(2):
        db_session['dst_ips'].append(generate_random_ip(DMZ_SUBNETS))
    
    session_groups.append(db_session)
    
    # 6. 원격 접속 트래픽 (내부->외부, 외부->DMZ, SSH/RDP)
    remote_session = {
        'count': int(num_logs * 0.05),  # 전체 트래픽의 5%
        'src_zone': 'Trust',
        'dst_zone': 'Untrust',
        'protocols': ['tcp'],
        'ports': [22, 3389],
        'src_ips': [],
        'dst_ips': [],
        'is_ipv6': False
    }
    
    # 내부 클라이언트 IP 10개 생성
    for _ in range(10):
        remote_session['src_ips'].append(generate_random_ip(INTERNAL_SUBNETS))
    
    # 외부 서버 IP 5개로 감소 (집중도 증가)
    for _ in range(5):
        remote_session['dst_ips'].append(generate_external_ip())
    
    session_groups.append(remote_session)
    
    # 7. IPv6 웹 트래픽 (내부->외부, HTTP/HTTPS)
    ipv6_web_session = {
        'count': int(num_logs * 0.07),  # 전체 트래픽의 7%
        'src_zone': 'Trust',
        'dst_zone': 'Untrust',
        'protocols': ['tcp'],
        'ports': [80, 443],
        'src_ips': [],
        'dst_ips': [],
        'is_ipv6': True
    }
    
    # 내부 IPv6 클라이언트 IP 20개 생성
    for _ in range(20):
        ipv6_web_session['src_ips'].append(generate_random_ip(IPV6_INTERNAL_SUBNETS))
    
    # 외부 IPv6 서버 IP - 주요 서비스에 집중
    for _ in range(10):
        ipv6_web_session['dst_ips'].append(generate_external_ip(is_ipv6=True))
    
    session_groups.append(ipv6_web_session)
    
    # 세션 그룹별로 로그 생성하기 전에 헤비 히터(heavy hitter) 연결 먼저 생성
    # 헤비 히터 로그 생성 (전체 트래픽의 80%)
    heavy_hitter_log_count = int(num_logs * heavy_hitter_percentage)
    
    # 핵심 연결의 로그 비율 계산 (파레토 분포)
    # zipf 분포를 사용하여 인기도에 따른 확률 분포 생성
    connection_weights = np.random.zipf(1.8, len(heavy_hitter_connections))
    ipv6_connection_weights = np.random.zipf(1.8, len(ipv6_heavy_hitter_connections))
    
    session_id_counter = 1
    connection_logs_generated = 0
    
    # IPv4 헤비 히터 로그 생성
    ipv4_log_count = int(heavy_hitter_log_count * IPV4_PERCENTAGE / 100)
    for _ in range(ipv4_log_count):
        # 가중치에 따라 연결 선택
        connection_idx = random.choices(
            range(len(heavy_hitter_connections)),
            weights=connection_weights,
            k=1
        )[0]
        
        src_ip, dst_ip, dst_port, protocol = heavy_hitter_connections[connection_idx]
        
        # 시간 간격은 24시간 내에서 랜덤
        time_offset = datetime.timedelta(seconds=random.randint(0, 86400))
        timestamp = base_time + time_offset
        
        # 세션 로그 생성
        log = None
        
        # 소스 포트, 패킷 정보, 정책 ID 등의 세부 정보 생성
        src_port = generate_port(dst=False, protocol=protocol)
        policy_name = generate_policy_name()
        interface = random.choice(INTERFACES)
        policy_id = generate_policy_id()
        packets_in, packets_out, byte_count = generate_packet_byte_info()
        
        # 액션과 종료 이유 설정
        action = random.choice(["CREATE", "CLOSE"])
        close_reason = ""
        if action == "CLOSE":
            close_reason = f"session closed {random.choice(CLOSE_REASONS)}: "
        
        # 영역 설정
        src_zone = "V1-Trust"
        dst_zone = "V1-Untrust"
        
        # 타임스탬프 포맷
        formatted_timestamp = timestamp.strftime("%b %d %H:%M:%S")
        
        # 호스트명
        hostname = "O_FW_1"
        
        # 프로토콜 번호 매핑
        protocol_num = PROTOCOL_NUMBER_MAP[protocol]
        
        # 세션 로그 생성
        log = SESSION_LOG_TEMPLATE.format(
            timestamp=formatted_timestamp,
            hostname=hostname,
            action=action,
            close_reason=close_reason,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol_num=protocol_num,
            session_id=session_id_counter,
            src_zone=src_zone,
            dst_zone=dst_zone,
            policy_id=policy_id,
            policy_name=policy_name,
            interface=interface,
            packets_in=packets_in,
            packets_out=packets_out,
            byte_count=byte_count
        )
        
        logs.append(log.strip())
        session_id_counter += 1
        connection_logs_generated += 1
    
    # IPv6 헤비 히터 로그 생성
    ipv6_log_count = heavy_hitter_log_count - ipv4_log_count
    for _ in range(ipv6_log_count):
        if len(ipv6_heavy_hitter_connections) == 0:
            break
            
        # 가중치에 따라 연결 선택
        connection_idx = random.choices(
            range(len(ipv6_heavy_hitter_connections)),
            weights=ipv6_connection_weights,
            k=1
        )[0]
        
        src_ip, dst_ip, dst_port, protocol = ipv6_heavy_hitter_connections[connection_idx]
        
        # 시간 간격은 24시간 내에서 랜덤
        time_offset = datetime.timedelta(seconds=random.randint(0, 86400))
        timestamp = base_time + time_offset
        
        # 세션 로그 생성
        src_port = generate_port(dst=False, protocol=protocol)
        policy_name = generate_policy_name()
        interface = random.choice(INTERFACES)
        policy_id = generate_policy_id()
        packets_in, packets_out, byte_count = generate_packet_byte_info()
        
        # 액션과 종료 이유 설정
        action = random.choice(["CREATE", "CLOSE"])
        close_reason = ""
        if action == "CLOSE":
            close_reason = f"session closed {random.choice(CLOSE_REASONS)}: "
        
        # 영역 설정
        src_zone = "V1-Trust"
        dst_zone = "V1-Untrust"
        
        # 타임스탬프 포맷
        formatted_timestamp = timestamp.strftime("%b %d %H:%M:%S")
        
        # 호스트명
        hostname = "O_FW_1"
        
        # 프로토콜 번호 매핑 (icmpv6 대응)
        protocol_num = PROTOCOL_NUMBER_MAP['icmpv6' if protocol == 'icmp' else protocol]
        
        # 세션 로그 생성
        log = SESSION_LOG_TEMPLATE.format(
            timestamp=formatted_timestamp,
            hostname=hostname,
            action=action,
            close_reason=close_reason,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol_num=protocol_num,
            session_id=session_id_counter,
            src_zone=src_zone,
            dst_zone=dst_zone,
            policy_id=policy_id,
            policy_name=policy_name,
            interface=interface,
            packets_in=packets_in,
            packets_out=packets_out,
            byte_count=byte_count
        )
        
        logs.append(log.strip())
        session_id_counter += 1
        connection_logs_generated += 1
    
    # 나머지 로그는 세션 그룹에서 생성
    remaining_logs = num_logs - connection_logs_generated
    
    # 세션 그룹별로 로그 생성
    for group in session_groups:
        count = min(int(group.get('count', 0) * remaining_logs / (num_logs - heavy_hitter_log_count)), remaining_logs)
        remaining_logs -= count
        
        is_ipv6 = group.get('is_ipv6', False)
        
        for _ in range(count):
            # 시간 간격은 24시간 내에서 랜덤
            time_offset = datetime.timedelta(seconds=random.randint(0, 86400))
            timestamp = base_time + time_offset
            
            # 그룹 내 랜덤 선택 (소스/대상 IP, 프로토콜, 포트)
            src_ip = random.choice(group['src_ips'])
            dst_ip = random.choice(group['dst_ips'])
            protocol = random.choice(group['protocols'])
            dst_port = random.choice(group['ports'])
            
            # 세션 로그 생성
            src_port = generate_port(dst=False, protocol=protocol)
            policy_name = generate_policy_name()
            interface = random.choice(INTERFACES)
            policy_id = generate_policy_id()
            packets_in, packets_out, byte_count = generate_packet_byte_info()
            
            # 액션과 종료 이유 설정
            action = random.choice(["CREATE", "CLOSE"])
            close_reason = ""
            if action == "CLOSE":
                close_reason = f"session closed {random.choice(CLOSE_REASONS)}: "
            
            # 영역 설정 (그룹에서 가져옴)
            src_zone = f"V1-{group['src_zone']}"
            dst_zone = f"V1-{group['dst_zone']}"
            
            # 타임스탬프 포맷
            formatted_timestamp = timestamp.strftime("%b %d %H:%M:%S")
            
            # 호스트명
            hostname = "O_FW_1"
            
            # 프로토콜 번호 매핑
            protocol_num = PROTOCOL_NUMBER_MAP[protocol]
            
            # 세션 로그 생성
            log = SESSION_LOG_TEMPLATE.format(
                timestamp=formatted_timestamp,
                hostname=hostname,
                action=action,
                close_reason=close_reason,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol_num=protocol_num,
                session_id=session_id_counter,
                src_zone=src_zone,
                dst_zone=dst_zone,
                policy_id=policy_id,
                policy_name=policy_name,
                interface=interface,
                packets_in=packets_in,
                packets_out=packets_out,
                byte_count=byte_count
            )
            
            logs.append(log.strip())
            session_id_counter += 1
    
    # 나머지는 완전 랜덤 로그로 채움
    for _ in range(remaining_logs):
        is_ipv6 = random.random() < (1 - IPV4_PERCENTAGE / 100)
        time_offset = datetime.timedelta(seconds=random.randint(0, 86400))
        timestamp = base_time + time_offset
        
        log = generate_session_log(session_id_counter, timestamp, is_ipv6)
        logs.append(log)
        session_id_counter += 1
    
    # 시간순으로 정렬
    logs.sort()
    
    return logs

def analyze_logs(logs):
    """
    생성된 로그를 분석하여 목적지 IP와 포트의 분포를 확인
    
    Args:
        logs (list): 생성된 로그 목록
        
    Returns:
        tuple: (목적지 IP 카운트, 목적지 포트 카운트, 소스 IP 카운트, 연결 카운트)
    """
    dst_ip_count = defaultdict(int)
    dst_port_count = defaultdict(int)
    src_ip_count = defaultdict(int)
    connection_count = defaultdict(int)
    
    for log in logs:
        parts = log.split()
        for i, part in enumerate(parts):
            if '->' in part:
                # src_ip/src_port->dst_ip/dst_port 형식 파싱
                src_dst = part.split('->')
                if len(src_dst) == 2:
                    src = src_dst[0].split('/')
                    dst = src_dst[1].split('/')
                    if len(src) == 2 and len(dst) == 2:
                        src_ip = src[0]
                        src_port = src[1]
                        dst_ip = dst[0]
                        dst_port = dst[1]
                        
                        # 연결 쌍 분석 (src_ip -> dst_ip:dst_port)
                        connection_key = f"{src_ip}->{dst_ip}:{dst_port}"
                        connection_count[connection_key] += 1
                        
                        # 소스 IP 집계
                        if ':' in src_ip:  # IPv6
                            try:
                                subnet_parts = src_ip.split(':')[:4]
                                subnet = ':'.join(subnet_parts)
                                src_ip_count[subnet + '::/64'] += 1
                            except:
                                src_ip_count[src_ip] += 1
                        else:  # IPv4
                            try:
                                ip_parts = src_ip.split('.')
                                subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                                src_ip_count[subnet] += 1
                            except:
                                src_ip_count[src_ip] += 1
                        
                        # IP 주소에서 서브넷 추출 (분석 용이성)
                        if ':' in dst_ip:  # IPv6
                            try:
                                # 간단한 IPv6 서브넷 추출 (처음 4개 필드)
                                subnet_parts = dst_ip.split(':')[:4]
                                subnet = ':'.join(subnet_parts)
                                dst_ip_count[subnet + '::/64'] += 1
                            except:
                                dst_ip_count[dst_ip] += 1
                        else:  # IPv4
                            try:
                                # x.y.z.0/24 형태의 서브넷으로 집계
                                ip_parts = dst_ip.split('.')
                                subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                                dst_ip_count[subnet] += 1
                            except:
                                dst_ip_count[dst_ip] += 1
                        
                        dst_port_count[dst_port] += 1
    
    return dst_ip_count, dst_port_count, src_ip_count, connection_count

def calculate_concentration_metrics(counts):
    """
    쏠림 현상 측정 지표 계산
    
    Args:
        counts (dict): 항목별 카운트 딕셔너리
        
    Returns:
        tuple: (지니 계수, 상위 10% 집중도, 상위 1% 집중도)
    """
    if not counts:
        return 0, 0, 0
        
    # 값 추출 및 정렬
    values = sorted(counts.values())
    total = sum(values)
    
    if total == 0:
        return 0, 0, 0
    
    # 지니 계수 계산
    n = len(values)
    index = np.arange(1, n + 1)
    gini = 2 * np.sum(index * values) / (n * total) - (n + 1) / n
    
    # 상위 집중도 계산
    top_10_percent_count = int(n * 0.1) or 1
    top_1_percent_count = max(int(n * 0.01), 1)
    
    top_10_percent = sum(values[-top_10_percent_count:]) / total * 100
    top_1_percent = sum(values[-top_1_percent_count:]) / total * 100
    
    return gini, top_10_percent, top_1_percent

def setup_syslog_client(server_host, server_port, protocol):
    """
    syslog 클라이언트 설정

    Args:
        server_host (str): syslog 서버 호스트
        server_port (int): syslog 서버 포트
        protocol (str): 사용할 프로토콜 ('tcp' 또는 'udp')

    Returns:
        logger: 설정된 logger 객체
    """
    # logger 설정
    logger = logging.getLogger('firewall_logs')
    logger.setLevel(logging.INFO)
    
    # 기존 핸들러 제거
    for handler in logger.handlers:
        logger.removeHandler(handler)
    
    # syslog 핸들러 설정
    if protocol.lower() == 'tcp':
        # TCP syslog 핸들러
        handler = logging.handlers.SysLogHandler(
            address=(server_host, server_port),
            facility=logging.handlers.SysLogHandler.LOG_LOCAL0,
            socktype=socket.SOCK_STREAM
        )
    else:
        # UDP syslog 핸들러 (기본값)
        handler = logging.handlers.SysLogHandler(
            address=(server_host, server_port),
            facility=logging.handlers.SysLogHandler.LOG_LOCAL0
        )
    
    # 포맷 제거 (날 것의 로그 메시지를 보내기 위해)
    handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(handler)
    
    return logger

def send_log_to_syslog(logger, log_message):
    """
    syslog 서버로 로그 메시지 전송

    Args:
        logger: logger 객체
        log_message (str): 전송할 로그 메시지
    
    Returns:
        bool: 전송 성공 여부
    """
    try:
        logger.info(log_message)
        return True
    except Exception as e:
        print(f"syslog 전송 오류: {e}", file=sys.stderr)
        return False

def realtime_log_generation(num_logs, output_file, syslog_logger=None, rate=10.0):
    """
    실시간 로그 생성 및 syslog 전송
    
    Args:
        num_logs (int): 생성할 로그 총 수
        output_file (str): 로그 저장 파일 경로
        syslog_logger: syslog 로거 객체
        rate (float): 로그 생성 및 전송 속도(초당 로그 수)
    """
    interval = 1.0 / rate
    logs_generated = 0
    
    # 실시간 모드이므로 파일에 계속 추가
    with open(output_file, 'a') as f:
        # 헤비 히터 연결 미리 생성
        heavy_hitter_connections = generate_connection_heavy_hitters(
            count=heavy_hitter_connection_count,
            is_ipv6=False
        )
        ipv6_heavy_hitter_connections = generate_connection_heavy_hitters(
            count=int(heavy_hitter_connection_count * 0.2),
            is_ipv6=True
        )
        
        # 연결 가중치 계산
        connection_weights = np.random.zipf(1.8, len(heavy_hitter_connections))
        ipv6_connection_weights = np.random.zipf(1.8, len(ipv6_heavy_hitter_connections))
        
        print("실시간 로그 생성 시작...")
        start_time = time.time()
        
        try:
            while logs_generated < num_logs:
                # 현재 진행 상황 표시 (100개마다)
                if logs_generated % 100 == 0:
                    elapsed = time.time() - start_time
                    estimated_total = elapsed / logs_generated * num_logs if logs_generated > 0 else 0
                    remaining = estimated_total - elapsed if logs_generated > 0 else 0
                    sys.stdout.write(f"\r로그 생성: {logs_generated}/{num_logs} ({logs_generated/num_logs*100:.1f}%) - "
                                    f"경과: {elapsed:.1f}초, 남은 시간: {remaining:.1f}초")
                    sys.stdout.flush()
                
                # 로그 타입 결정 (헤비 히터 vs 일반)
                is_heavy_hitter = random.random() < heavy_hitter_percentage
                is_ipv6 = random.random() < (1 - IPV4_PERCENTAGE / 100)
                
                # 로그 생성
                log = None
                
                if is_heavy_hitter:
                    if is_ipv6 and ipv6_heavy_hitter_connections:
                        # IPv6 헤비 히터 연결
                        connection_idx = random.choices(
                            range(len(ipv6_heavy_hitter_connections)),
                            weights=ipv6_connection_weights,
                            k=1
                        )[0]
                        
                        src_ip, dst_ip, dst_port, protocol = ipv6_heavy_hitter_connections[connection_idx]
                        
                        # 시간은 최근으로 (실시간 모드이므로)
                        time_offset = datetime.timedelta(seconds=random.randint(0, 300))  # 최근 5분 내
                        timestamp = datetime.datetime.now() - time_offset
                        
                        # 세션 로그 생성 - 실제 로그에 가깝게 모든 필요한 필드 포함
                        session_id = generate_session_id()
                        src_port = generate_port(dst=False, protocol=protocol)
                        policy_name = generate_policy_name()
                        interface = random.choice(INTERFACES)
                        policy_id = generate_policy_id()
                        packets_in, packets_out, byte_count = generate_packet_byte_info()
                        
                        # 액션과 종료 이유 설정
                        action = random.choice(["CREATE", "CLOSE"])
                        close_reason = ""
                        if action == "CLOSE":
                            close_reason = f"session closed {random.choice(CLOSE_REASONS)}: "
                        
                        # 영역 설정
                        src_zone = "V1-Trust"
                        dst_zone = "V1-Untrust"
                        
                        # 타임스탬프 포맷
                        formatted_timestamp = timestamp.strftime("%b %d %H:%M:%S")
                        
                        # 호스트명
                        hostname = "O_FW_1"
                        
                        # 프로토콜 번호 매핑 (icmpv6 대응)
                        protocol_num = PROTOCOL_NUMBER_MAP['icmpv6' if protocol == 'icmp' else protocol]
                        
                        # 실제 로그 형식에 맞는 세션 로그 생성
                        log = SESSION_LOG_TEMPLATE.format(
                            timestamp=formatted_timestamp,
                            hostname=hostname,
                            action=action,
                            close_reason=close_reason,
                            src_ip=src_ip,
                            src_port=src_port,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            protocol_num=protocol_num,
                            session_id=session_id,
                            src_zone=src_zone,
                            dst_zone=dst_zone,
                            policy_id=policy_id,
                            policy_name=policy_name,
                            interface=interface,
                            packets_in=packets_in,
                            packets_out=packets_out,
                            byte_count=byte_count
                        )
                    
                    elif not is_ipv6 and heavy_hitter_connections:
                        # IPv4 헤비 히터 연결
                        connection_idx = random.choices(
                            range(len(heavy_hitter_connections)),
                            weights=connection_weights,
                            k=1
                        )[0]
                        
                        src_ip, dst_ip, dst_port, protocol = heavy_hitter_connections[connection_idx]
                        
                        # 시간은 최근으로 (실시간 모드이므로)
                        time_offset = datetime.timedelta(seconds=random.randint(0, 300))  # 최근 5분 내
                        timestamp = datetime.datetime.now() - time_offset
                        
                        # 세션 로그 생성 - 실제 로그에 가깝게 모든 필요한 필드 포함
                        session_id = generate_session_id()
                        src_port = generate_port(dst=False, protocol=protocol)
                        policy_name = generate_policy_name()
                        interface = random.choice(INTERFACES)
                        policy_id = generate_policy_id()
                        packets_in, packets_out, byte_count = generate_packet_byte_info()
                        
                        # 액션과 종료 이유 설정
                        action = random.choice(["CREATE", "CLOSE"])
                        close_reason = ""
                        if action == "CLOSE":
                            close_reason = f"session closed {random.choice(CLOSE_REASONS)}: "
                        
                        # 영역 설정
                        src_zone = "V1-Trust"
                        dst_zone = "V1-Untrust"
                        
                        # 타임스탬프 포맷
                        formatted_timestamp = timestamp.strftime("%b %d %H:%M:%S")
                        
                        # 호스트명
                        hostname = "O_FW_1"
                        
                        # 프로토콜 번호 매핑
                        protocol_num = PROTOCOL_NUMBER_MAP[protocol]
                        
                        # 세션 로그 생성
                        log = SESSION_LOG_TEMPLATE.format(
                            timestamp=formatted_timestamp,
                            hostname=hostname,
                            action=action,
                            close_reason=close_reason,
                            src_ip=src_ip,
                            src_port=src_port,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            protocol_num=protocol_num,
                            session_id=session_id,
                            src_zone=src_zone,
                            dst_zone=dst_zone,
                            policy_id=policy_id,
                            policy_name=policy_name,
                            interface=interface,
                            packets_in=packets_in,
                            packets_out=packets_out,
                            byte_count=byte_count
                        )
                
                # 헤비 히터 연결이 없거나 일반 연결인 경우
                if log is None:
                    # 일반 랜덤 연결 로그 생성
                    timestamp = datetime.datetime.now() - datetime.timedelta(seconds=random.randint(0, 300))
                    session_id = generate_session_id()
                    log = generate_session_log(session_id, timestamp, is_ipv6)
                
                # 로그 파일에 쓰기
                f.write(log + '\n')
                f.flush()  # 실시간 모드에서는 즉시 파일에 쓰기
                
                # syslog로 전송 (설정된 경우)
                if syslog_logger:
                    send_log_to_syslog(syslog_logger, log)
                
                logs_generated += 1
                
                # 설정된 속도에 맞게 지연
                time.sleep(interval)
        
        except KeyboardInterrupt:
            print("\n사용자에 의해 중단되었습니다.")
        
        # 최종 진행 상황 표시
        elapsed = time.time() - start_time
        print(f"\n실시간 로그 생성 완료: {logs_generated}개 생성 (소요 시간: {elapsed:.1f}초)")
        print(f"파일 저장 위치: {os.path.abspath(output_file)}")

def main():
    """
    메인 함수 - 로그 생성 및 분석
    """
    parser = argparse.ArgumentParser(
        description='실제와 유사한 방화벽 세션 로그 생성기'
    )
    
    parser.add_argument('--num-logs', type=int, default=100000,
                       help='생성할 로그 수 (기본값: 100000)')
    parser.add_argument('--output-file', default='fw_session_logs.log',
                       help='출력 파일 경로 (기본값: fw_session_logs.log)')
    parser.add_argument('--ipv6-ratio', type=float, default=15.0,
                       help='IPv6 로그의 비율(퍼센트) (기본값: 15.0)')
    parser.add_argument('--heavy-hitter-ratio', type=float, default=80.0,
                       help='헤비 히터 연결의 트래픽 비율(퍼센트) (기본값: 80.0)')
    parser.add_argument('--heavy-hitter-count', type=int, default=50,
                       help='헤비 히터 연결 수 (기본값: 50)')
    parser.add_argument('--analyze', action='store_true',
                       help='생성된 로그 분석 수행 여부')
    parser.add_argument('--detailed-analysis', action='store_true',
                       help='상세 분석 (연결 및 쏠림 현상 지표 계산)')
    parser.add_argument('--top-n', type=int, default=20,
                       help='분석 시 상위 표시할 항목 수 (기본값: 20)')
    
    # Syslog 관련 인수 추가
    parser.add_argument('--syslog', action='store_true',
                       help='syslog 서버로 로그 전송 활성화')
    parser.add_argument('--syslog-server', default='127.0.0.1',
                       help='syslog 서버 주소 (기본값: 127.0.0.1)')
    parser.add_argument('--syslog-port', type=int, default=514,
                       help='syslog 서버 포트 (기본값: 514)')
    parser.add_argument('--syslog-protocol', default='udp', choices=['tcp', 'udp'],
                       help='syslog 전송 프로토콜 (기본값: udp)')
    parser.add_argument('--syslog-rate', type=float, default=10.0,
                       help='syslog 전송 속도(초당 로그 수) (기본값: 10.0)')
    parser.add_argument('--realtime', action='store_true',
                       help='실시간 로그 생성 및 전송 모드')
                       
    args = parser.parse_args()
    
    # IPv6 비율 설정
    global IPV4_PERCENTAGE
    IPV4_PERCENTAGE = 100 - args.ipv6_ratio
    
    # 헤비 히터 비율 설정
    global heavy_hitter_percentage, heavy_hitter_connection_count
    heavy_hitter_percentage = args.heavy_hitter_ratio / 100.0
    heavy_hitter_connection_count = args.heavy_hitter_count
    
    print(f"방화벽 세션 로그 {args.num_logs}개 생성 중... (실제 주니퍼 방화벽 로그 포맷 적용)")
    print(f"* 쏠림 현상 설정: 상위 {args.heavy_hitter_count}개 연결이 전체 트래픽의 {args.heavy_hitter_ratio:.1f}% 차지")
    
    # syslog 설정
    syslog_logger = None
    if args.syslog:
        print(f"* syslog 전송 활성화: {args.syslog_server}:{args.syslog_port} ({args.syslog_protocol})")
        try:
            syslog_logger = setup_syslog_client(
                args.syslog_server, args.syslog_port, args.syslog_protocol
            )
        except Exception as e:
            print(f"syslog 설정 오류: {e}")
            print("syslog 전송 없이 계속합니다.")
    
    # 실시간 모드 처리
    if args.realtime:
        print(f"* 실시간 로그 생성 모드 활성화 (속도: {args.syslog_rate} 로그/초)")
        realtime_log_generation(
            num_logs=args.num_logs, 
            output_file=args.output_file, 
            syslog_logger=syslog_logger, 
            rate=args.syslog_rate
        )
        return
    
    # 일괄 로그 생성
    logs = generate_realistic_traffic_patterns(args.num_logs)
    
    # 로그 파일 저장
    with open(args.output_file, 'w') as f:
        for log in logs:
            f.write(log + '\n')
    
    print(f"생성 완료! 파일 저장 위치: {os.path.abspath(args.output_file)}")
    
    # syslog 전송 (필요시)
    if args.syslog and syslog_logger:
        print(f"로그를 syslog 서버({args.syslog_server}:{args.syslog_port})로 전송 중...")
        
        if args.syslog_rate > 0:
            interval = 1.0 / args.syslog_rate
            
            for i, log in enumerate(logs):
                send_success = send_log_to_syslog(syslog_logger, log)
                if i % 100 == 0:
                    sys.stdout.write(f"\r전송 진행률: {i}/{len(logs)} ({i/len(logs)*100:.1f}%)")
                    sys.stdout.flush()
                time.sleep(interval)
            
            print("\nsyslog 전송 완료!")
        else:
            print("전송 속도가 0 이하로 설정되어 syslog 전송을 건너뜁니다.")
    
    # 간단한 통계 출력
    protocols = defaultdict(int)
    zones = defaultdict(int)
    ipv4_count = 0
    ipv6_count = 0
    
    for log in logs:
        parts = log.split()
        
        # 프로토콜 ID 추출
        for i, part in enumerate(parts):
            if i > 0 and parts[i-1] == "N/A" and parts[i+1].isdigit():
                protocol_id = int(parts[i+1])
                # 프로토콜 ID를 이름으로 변환
                if protocol_id == 6:
                    protocols["tcp"] += 1
                elif protocol_id == 17:
                    protocols["udp"] += 1
                elif protocol_id == 1:
                    protocols["icmp"] += 1
                elif protocol_id == 58:
                    protocols["icmpv6"] += 1
                else:
                    protocols[f"unknown({protocol_id})"] += 1
        
        # 영역 추출
        for i, part in enumerate(parts):
            if "V1-" in part and i < len(parts) - 1 and "V1-" in parts[i+1]:
                zones[(part, parts[i+1])] += 1  # (src_zone, dst_zone)
        
        # IP 버전 카운트
        for part in parts:
            if '->' in part:
                src_dst = part.split('->')
                if ':' in src_dst[0]:  # IPv6 주소 확인
                    ipv6_count += 1
                    break
                else:
                    ipv4_count += 1
                    break
    
    print("\n=== 생성된 로그 통계 ===")
    print(f"총 로그 수: {len(logs)}")
    print(f"IPv4 로그 수: {ipv4_count} ({ipv4_count/len(logs)*100:.1f}%)")
    print(f"IPv6 로그 수: {ipv6_count} ({ipv6_count/len(logs)*100:.1f}%)")
    
    print("\n프로토콜 분포:")
    for protocol, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
        print(f"  {protocol}: {count} ({count/len(logs)*100:.1f}%)")
    
    print("\n영역 쌍 분포:")
    for (src, dst), count in sorted(zones.items(), key=lambda x: x[1], reverse=True):
        print(f"  {src}->{dst}: {count} ({count/len(logs)*100:.1f}%)")
    
    # 로그 분석 (목적지 IP와 포트 집중도)
    if args.analyze:
        print("\n=== 목적지 IP/포트 분포 분석 ===")
        print("(실제 인터넷 트래픽과 유사한 목적지 쏠림 현상 확인)")
        
        dst_ip_count, dst_port_count, src_ip_count, connection_count = analyze_logs(logs)
        
        # 상위 목적지 IP 출력
        print(f"\n상위 {args.top_n}개 목적지 IP (서브넷):")
        total_ips = sum(dst_ip_count.values())
        cumulative_percent = 0
        
        for i, (ip, count) in enumerate(sorted(dst_ip_count.items(), key=lambda x: x[1], reverse=True)[:args.top_n]):
            percent = count / total_ips * 100
            cumulative_percent += percent
            print(f"  {i+1:2d}. {ip:30s}: {count:6d} ({percent:5.1f}%, 누적: {cumulative_percent:5.1f}%)")
        
        # 목적지 IP 쏠림 현상 지표
        dst_ip_gini, dst_ip_top10, dst_ip_top1 = calculate_concentration_metrics(dst_ip_count)
        print(f"\n  * 목적지 IP 쏠림 현상 지표:")
        print(f"    - 지니 계수: {dst_ip_gini:.4f} (0: 완전 균등, 1: 완전 집중)")
        print(f"    - 상위 10% 집중도: {dst_ip_top10:.1f}%")
        print(f"    - 상위 1% 집중도: {dst_ip_top1:.1f}%")
        
        # 상위 목적지 포트 출력
        print(f"\n상위 {min(args.top_n, 15)}개 목적지 포트:")
        total_ports = sum(dst_port_count.values())
        cumulative_percent = 0
        
        for i, (port, count) in enumerate(sorted(dst_port_count.items(), key=lambda x: x[1], reverse=True)[:min(args.top_n, 15)]):
            percent = count / total_ports * 100
            cumulative_percent += percent
            
            # 잘 알려진 포트 이름 표시
            port_name = ""
            if port == "80": port_name = "(HTTP)"
            elif port == "443": port_name = "(HTTPS)"
            elif port == "53": port_name = "(DNS)"
            elif port == "22": port_name = "(SSH)"
            elif port == "25": port_name = "(SMTP)"
            elif port == "21": port_name = "(FTP)"
            elif port == "3389": port_name = "(RDP)"
            
            print(f"  {i+1:2d}. Port {port:5s} {port_name:8s}: {count:6d} ({percent:5.1f}%, 누적: {cumulative_percent:5.1f}%)")
        
        # 목적지 포트 쏠림 현상 지표
        dst_port_gini, dst_port_top10, dst_port_top1 = calculate_concentration_metrics(dst_port_count)
        print(f"\n  * 목적지 포트 쏠림 현상 지표:")
        print(f"    - 지니 계수: {dst_port_gini:.4f} (0: 완전 균등, 1: 완전 집중)")
        print(f"    - 상위 10% 집중도: {dst_port_top10:.1f}%")
        print(f"    - 상위 1% 집중도: {dst_port_top1:.1f}%")
        
        # 상세 분석 - 연결 쌍 집중도
        if args.detailed_analysis:
            print("\n=== 연결 집중도 상세 분석 ===")
            print(f"\n상위 {min(args.top_n, 10)}개 연결 쌍 (src_ip->dst_ip:dst_port):")
            total_connections = sum(connection_count.values())
            cumulative_percent = 0
            
            for i, (conn, count) in enumerate(sorted(connection_count.items(), key=lambda x: x[1], reverse=True)[:min(args.top_n, 10)]):
                percent = count / total_connections * 100
                cumulative_percent += percent
                print(f"  {i+1:2d}. {conn:50s}: {count:6d} ({percent:5.1f}%, 누적: {cumulative_percent:5.1f}%)")
            
            # 연결 쏠림 현상 지표
            conn_gini, conn_top10, conn_top1 = calculate_concentration_metrics(connection_count)
            print(f"\n  * 연결 쌍 쏠림 현상 지표:")
            print(f"    - 지니 계수: {conn_gini:.4f} (0: 완전 균등, 1: 완전 집중)")
            print(f"    - 상위 10% 집중도: {conn_top10:.1f}%")
            print(f"    - 상위 1% 집중도: {conn_top1:.1f}%")
            print(f"    - 상위 {args.heavy_hitter_count}개 연결의 비율: {args.heavy_hitter_ratio:.1f}% (목표)")
            
            unique_connection_count = len(connection_count)
            print(f"\n  * 고유 연결 쌍 수: {unique_connection_count}")
            print(f"    - 전체 로그 대비 비율: {unique_connection_count/len(logs)*100:.2f}%")
            
            # 트래픽 분포 로렌츠 곡선 데이터 계산
            print("\n  * 트래픽 분포 데이터 (로렌츠 곡선):")
            percentiles = [10, 20, 30, 40, 50, 60, 70, 80, 90, 95, 99, 100]
            values = sorted(connection_count.values())
            total = sum(values)
            cumulative = 0
            
            print("    백분위수 | 트래픽 비율")
            print("    ---------|------------")
            for p in percentiles:
                idx = min(int(len(values) * p / 100), len(values) - 1)
                cumulative = sum(values[:idx+1])
                print(f"    {p:3d}%    | {cumulative/total*100:6.2f}%")

if __name__ == "__main__":
    main()
