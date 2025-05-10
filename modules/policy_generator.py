#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
방화벽 정책 추천 시스템 - 정책 생성기
----------------------------------
트래픽 분석 결과를 기반으로 방화벽 정책을 생성합니다.
"""

import logging
import ipaddress
from datetime import datetime

logger = logging.getLogger(__name__)

class PolicyGenerator:
    """주니퍼 방화벽 설정을 생성하는 클래스"""
    
    def __init__(self, policies=None):
        """
        초기화
        
        Args:
            policies (list): 정책 리스트 (딕셔너리 형태)
        """
        self.policies = policies or []
    
    def generate_juniper_config(self):
        """
        주니퍼 방화벽 설정 생성
        
        Returns:
            str: 주니퍼 방화벽 설정 문자열
        """
        if not self.policies:
            logger.warning("정책이 없어 방화벽 설정을 생성할 수 없습니다!")
            return ""
        
        logger.info(f"{len(self.policies)}개 정책에 대한 주니퍼 방화벽 설정 생성 중...")
        
        config_lines = []
        
        # 설정 헤더 추가
        config_lines.append("# 주니퍼 방화벽 정책 설정")
        config_lines.append("# 생성 시간: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        config_lines.append("")
        
        # IPv4 정책과 IPv6 정책 분리
        ipv4_policies = [p for p in self.policies if not p.get('is_ipv6', False)]
        ipv6_policies = [p for p in self.policies if p.get('is_ipv6', False)]
        
        # IPv4 정책 생성
        if ipv4_policies:
            config_lines.append("# IPv4 정책")
            config_lines.append("")
            
            # 주소집합(address-book) 생성
            config_lines.append("# 주소집합 정의")
            config_lines.append("set security address-book global")
            
            # 소스 주소 집합
            src_addresses = {}
            for policy in ipv4_policies:
                policy_name = policy['name']
                for i, network in enumerate(policy.get('src_networks', [])):
                    address_name = f"src-{policy_name}-{i}"
                    src_addresses[address_name] = network
                    config_lines.append(f"set security address-book global address {address_name} {network}")
            
            # 목적지 주소 집합
            dst_addresses = {}
            for policy in ipv4_policies:
                policy_name = policy['name']
                for i, network in enumerate(policy.get('dst_networks', [])):
                    address_name = f"dst-{policy_name}-{i}"
                    dst_addresses[address_name] = network
                    config_lines.append(f"set security address-book global address {address_name} {network}")
            
            config_lines.append("")
            
            # 애플리케이션 정의 (포트와 프로토콜)
            config_lines.append("# 애플리케이션 정의")
            
            applications = {}
            for policy in ipv4_policies:
                policy_name = policy['name']
                protocols = policy.get('protocols', [])
                port_ranges = policy.get('port_ranges', [])
                
                if not protocols or not port_ranges:
                    continue
                
                for protocol in protocols:
                    for i, port_range in enumerate(port_ranges):
                        app_name = f"app-{policy_name}-{protocol}-{i}"
                        applications[app_name] = (protocol, port_range)
                        
                        # 프로토콜별 설정
                        if protocol in ('tcp', 'udp'):
                            start_port, end_port = port_range.split('-')
                            config_lines.append(f"set applications application {app_name} protocol {protocol}")
                            config_lines.append(f"set applications application {app_name} destination-port {start_port}-{end_port}")
                        elif protocol in ('icmp', 'icmpv6'):
                            config_lines.append(f"set applications application {app_name} protocol {protocol}")
                
            config_lines.append("")
            
            # 정책 정의
            config_lines.append("# 정책 정의")
            
            for policy in ipv4_policies:
                policy_name = policy['name']
                src_zones = policy.get('src_zones', ['trust'])
                dst_zones = policy.get('dst_zones', ['untrust'])
                
                # 각 존 조합에 대한 정책 생성
                for src_zone in src_zones:
                    for dst_zone in dst_zones:
                        # 소스 주소 정의
                        src_addresses_for_policy = [f"src-{policy_name}-{i}" 
                                                   for i in range(len(policy.get('src_networks', [])))]
                        
                        # 목적지 주소 정의
                        dst_addresses_for_policy = [f"dst-{policy_name}-{i}" 
                                                   for i in range(len(policy.get('dst_networks', [])))]
                        
                        # 애플리케이션 정의
                        applications_for_policy = []
                        for protocol in policy.get('protocols', []):
                            for i in range(len(policy.get('port_ranges', []))):
                                app_name = f"app-{policy_name}-{protocol}-{i}"
                                if app_name in applications:
                                    applications_for_policy.append(app_name)
                        
                        # 정책 이름
                        zone_policy_name = f"{policy_name}-{src_zone}-to-{dst_zone}"
                        
                        # 정책 설정
                        config_lines.append(f"# 정책: {zone_policy_name}")
                        config_lines.append(f"set security policies from-zone {src_zone} to-zone {dst_zone} policy {zone_policy_name}")
                        
                        # 소스 주소
                        if src_addresses_for_policy:
                            for addr in src_addresses_for_policy:
                                config_lines.append(f"set security policies from-zone {src_zone} to-zone {dst_zone} policy {zone_policy_name} match source-address {addr}")
                        else:
                            config_lines.append(f"set security policies from-zone {src_zone} to-zone {dst_zone} policy {zone_policy_name} match source-address any")
                        
                        # 목적지 주소
                        if dst_addresses_for_policy:
                            for addr in dst_addresses_for_policy:
                                config_lines.append(f"set security policies from-zone {src_zone} to-zone {dst_zone} policy {zone_policy_name} match destination-address {addr}")
                        else:
                            config_lines.append(f"set security policies from-zone {src_zone} to-zone {dst_zone} policy {zone_policy_name} match destination-address any")
                        
                        # 애플리케이션
                        if applications_for_policy:
                            for app in applications_for_policy:
                                config_lines.append(f"set security policies from-zone {src_zone} to-zone {dst_zone} policy {zone_policy_name} match application {app}")
                        else:
                            config_lines.append(f"set security policies from-zone {src_zone} to-zone {dst_zone} policy {zone_policy_name} match application any")
                        
                        # 정책 액션 (기본: 허용)
                        config_lines.append(f"set security policies from-zone {src_zone} to-zone {dst_zone} policy {zone_policy_name} then permit")
                        config_lines.append(f"set security policies from-zone {src_zone} to-zone {dst_zone} policy {zone_policy_name} then log session-init")
                        config_lines.append(f"set security policies from-zone {src_zone} to-zone {dst_zone} policy {zone_policy_name} then log session-close")
                        
                        config_lines.append("")
        
        # IPv6 정책 생성 (위와 유사한 로직)
        if ipv6_policies:
            config_lines.append("# IPv6 정책")
            config_lines.append("")
            
            # IPv6 주소집합 정의
            # IPv4와 유사한 설정 형식 사용
            # ...
        
        # 설정 푸터 추가
        config_lines.append("# 설정 끝")
        
        # 설정 문자열 반환
        return "\n".join(config_lines)
    
    def generate_cisco_asa_config(self):
        """
        Cisco ASA 방화벽 설정 생성
        
        Returns:
            str: Cisco ASA 방화벽 설정 문자열
        """
        # 향후 Cisco ASA 설정 생성 기능 구현 시 사용
        # ...
        return ""
    
    def generate_firewalld_config(self):
        """
        firewalld 설정 생성 (리눅스)
        
        Returns:
            str: firewalld 설정 문자열
        """
        # 향후 firewalld 설정 생성 기능 구현 시 사용
        # ...
        return ""
