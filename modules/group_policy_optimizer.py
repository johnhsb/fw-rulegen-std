#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
방화벽 정책 최적화 모듈 - 그룹 기반 정책 생성
--------------------------------------------------
트래픽 분석 결과를 바탕으로 주소/포트 그룹을 생성하고
최적화된 정책을 생성합니다.
"""

import logging
import ipaddress
from collections import defaultdict
from typing import List, Dict, Set, Tuple, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class GroupBasedPolicyOptimizer:
    """그룹 기반 정책 최적화기"""
    
    def __init__(self, policies: List[Dict], min_usage_threshold: int = 3):
        self.policies = policies
        self.min_usage_threshold = min_usage_threshold
        
        # 그룹 정의
        self.address_groups = {'source': {}, 'destination': {}}
        self.port_groups = {}
        
        # 사용 통계
        self.address_usage = defaultdict(int)
        self.port_usage = defaultdict(int)
        
        # 최적화된 정책
        self.optimized_policies = []
        
    def analyze_and_optimize(self) -> Dict[str, Any]:
        """전체 분석 및 최적화 수행"""
        logger.info("그룹 기반 정책 최적화 시작...")
        
        # 1. 사용 패턴 분석
        self._analyze_usage_patterns()
        
        # 2. 그룹 정의
        self._create_address_groups()
        self._create_port_groups()
        
        # 3. 정책 최적화
        self._optimize_policies()
        
        optimization_result = {
            'address_groups': self.address_groups,
            'port_groups': self.port_groups,
            'optimized_policies': self.optimized_policies,
            'optimization_stats': self._get_optimization_stats()
        }
        
        logger.info(f"정책 최적화 완료: {len(self.policies)} -> {len(self.optimized_policies)}개 정책")
        return optimization_result
    
    def _analyze_usage_patterns(self):
        """사용 패턴 분석"""
        for policy in self.policies:
            traffic_count = policy.get('traffic_count', 1)
            
            # 출발지 주소 사용 통계
            for network in policy.get('src_networks', []):
                self.address_usage[('src', network)] += traffic_count
            
            # 목적지 주소 사용 통계
            for network in policy.get('dst_networks', []):
                self.address_usage[('dst', network)] += traffic_count
            
            # 포트 사용 통계
            for port_range in policy.get('port_ranges', []):
                self.port_usage[port_range] += traffic_count
    
    def _create_address_groups(self):
        """주소 그룹 생성"""
        src_addresses = {}
        dst_addresses = {}
        
        for (addr_type, network), usage in self.address_usage.items():
            if usage >= self.min_usage_threshold:
                if addr_type == 'src':
                    src_addresses[network] = usage
                else:
                    dst_addresses[network] = usage
        
        self.address_groups['source'] = self._group_similar_networks(src_addresses, 'SRC')
        self.address_groups['destination'] = self._group_similar_networks(dst_addresses, 'DST')
    
    def _group_similar_networks(self, address_usage: Dict, prefix: str) -> Dict[str, List[str]]:
        """유사한 네트워크를 그룹화"""
        groups = {}
        grouped_networks = set()
        
        # 서브넷 기반 그룹화
        subnet_groups = defaultdict(list)
        for network in address_usage.keys():
            try:
                net_obj = ipaddress.ip_network(network, strict=False)
                if net_obj.version == 4:
                    if net_obj.prefixlen >= 24:
                        parent_subnet = str(ipaddress.IPv4Network(f"{net_obj.network_address}/24", strict=False))
                    else:
                        parent_subnet = str(ipaddress.IPv4Network(f"{net_obj.network_address}/16", strict=False))
                else:  # IPv6
                    parent_subnet = str(ipaddress.IPv6Network(f"{net_obj.network_address}/64", strict=False))
                
                subnet_groups[parent_subnet].append(network)
            except ValueError:
                continue
        
        # 그룹 생성
        group_counter = 1
        for parent_subnet, networks in subnet_groups.items():
            if len(networks) >= 2:
                group_name = f"{prefix}_GROUP_{group_counter:02d}"
                groups[group_name] = networks
                grouped_networks.update(networks)
                group_counter += 1
        
        # 자주 사용되는 개별 주소
        high_usage_networks = [
            network for network, usage in address_usage.items() 
            if usage >= self.min_usage_threshold * 2 and network not in grouped_networks
        ]
        
        if high_usage_networks:
            groups[f"{prefix}_HIGH_USAGE"] = high_usage_networks
        
        return groups
    
    def _create_port_groups(self):
        """포트 그룹 생성"""
        frequent_ports = [
            port_range for port_range, usage in self.port_usage.items()
            if usage >= self.min_usage_threshold
        ]
        
        # 포트 유형별 분류
        web_ports = []
        database_ports = []
        management_ports = []
        other_ports = []
        
        for port_range in frequent_ports:
            start_port = self._get_start_port(port_range)
            
            if start_port in [80, 443, 8080, 8443, 8000, 8888, 9000]:
                web_ports.append(port_range)
            elif start_port in [3306, 5432, 1521, 1433, 27017]:
                database_ports.append(port_range)
            elif start_port in [22, 23, 161, 162, 3389]:
                management_ports.append(port_range)
            else:
                other_ports.append(port_range)
        
        if web_ports:
            self.port_groups['WEB_PORTS'] = web_ports
        if database_ports:
            self.port_groups['DATABASE_PORTS'] = database_ports
        if management_ports:
            self.port_groups['MANAGEMENT_PORTS'] = management_ports
        if len(other_ports) >= 2:
            self.port_groups['COMMON_PORTS'] = other_ports
    
    def _get_start_port(self, port_range: str) -> int:
        """포트 범위에서 시작 포트 추출"""
        if '-' in port_range:
            return int(port_range.split('-')[0])
        return int(port_range)
    
    def _optimize_policies(self):
        """정책 최적화"""
        policy_matrix = self._build_policy_matrix()
        self.optimized_policies = self._generate_optimized_policies(policy_matrix)
    
    def _build_policy_matrix(self) -> Dict[Tuple, Dict]:
        """정책 매트릭스 생성"""
        matrix = defaultdict(lambda: {
            'protocols': set(),
            'traffic_count': 0,
            'policy_ids': [],
            'src_zones': set(),
            'dst_zones': set()
        })
        
        for policy in self.policies:
            src_group = self._find_address_group(policy.get('src_networks', []), 'source')
            dst_group = self._find_address_group(policy.get('dst_networks', []), 'destination')
            port_group = self._find_port_group(policy.get('port_ranges', []))
            
            key = (src_group, dst_group, port_group)
            
            matrix[key]['protocols'].update(policy.get('protocols', []))
            matrix[key]['traffic_count'] += policy.get('traffic_count', 1)
            matrix[key]['policy_ids'].append(policy.get('id', ''))
            matrix[key]['src_zones'].update(policy.get('src_zones', ['trust']))
            matrix[key]['dst_zones'].update(policy.get('dst_zones', ['untrust']))
        
        return matrix
    
    def _find_address_group(self, networks: List[str], group_type: str) -> str:
        """주소 그룹 찾기"""
        if not networks:
            return 'any'
        
        # 정의된 그룹에서 찾기
        for group_name, group_networks in self.address_groups.get(group_type, {}).items():
            if set(networks).issubset(set(group_networks)):
                return group_name
        
        # 개별 네트워크
        if len(networks) == 1:
            return f"addr_{networks[0].replace('/', '_').replace(':', '_')}"
        
        # 임시 그룹
        return f"temp_{group_type}_{abs(hash(tuple(sorted(networks)))) % 10000:04d}"
    
    def _find_port_group(self, port_ranges: List[str]) -> str:
        """포트 그룹 찾기"""
        if not port_ranges:
            return 'any'
        
        # 정의된 그룹에서 찾기
        for group_name, group_ports in self.port_groups.items():
            if set(port_ranges).issubset(set(group_ports)):
                return group_name
        
        # 개별 포트
        if len(port_ranges) == 1:
            return f"port_{port_ranges[0].replace('-', '_')}"
        
        # 임시 그룹
        return f"temp_ports_{abs(hash(tuple(sorted(port_ranges)))) % 10000:04d}"
    
    def _generate_optimized_policies(self, matrix: Dict) -> List[Dict]:
        """최적화된 정책 생성"""
        policies = []
        policy_counter = 1
        
        for (src_group, dst_group, port_group), data in matrix.items():
            policy = {
                'name': f"OPTIMIZED_POLICY_{policy_counter:03d}",
                'id': f"OPT{policy_counter:03d}",
                'src_networks': self._resolve_group_to_networks(src_group, 'source'),
                'dst_networks': self._resolve_group_to_networks(dst_group, 'destination'),
                'port_ranges': self._resolve_group_to_ports(port_group),
                'protocols': list(data['protocols']),
                'src_zones': list(data['src_zones']),
                'dst_zones': list(data['dst_zones']),
                'service_names': self._extract_service_names(port_group),
                'traffic_count': data['traffic_count'],
                'is_ipv6': False,
                'is_optimized': True,
                'group_info': {
                    'src_group': src_group,
                    'dst_group': dst_group,
                    'port_group': port_group
                },
                'original_policies': data['policy_ids']
            }
            
            policies.append(policy)
            policy_counter += 1
        
        # 트래픽 양 기준으로 정렬
        policies.sort(key=lambda x: x['traffic_count'], reverse=True)
        return policies
    
    def _resolve_group_to_networks(self, group_name: str, group_type: str) -> List[str]:
        """그룹을 실제 네트워크 리스트로 변환"""
        if group_name == 'any':
            return ['any']
        
        if group_name.startswith('addr_'):
            # 개별 주소
            addr = group_name[5:].replace('_', '/').replace('/', ':', 1)  # IPv6 처리
            return [addr]
        
        # 그룹에서 찾기
        group_networks = self.address_groups.get(group_type, {}).get(group_name, [])
        return group_networks if group_networks else [group_name]
    
    def _resolve_group_to_ports(self, group_name: str) -> List[str]:
        """그룹을 실제 포트 리스트로 변환"""
        if group_name == 'any':
            return ['any']
        
        if group_name.startswith('port_'):
            port = group_name[5:].replace('_', '-')
            return [port]
        
        # 그룹에서 찾기
        group_ports = self.port_groups.get(group_name, [])
        return group_ports if group_ports else [group_name]
    
    def _extract_service_names(self, port_group: str) -> List[str]:
        """포트 그룹에서 서비스 이름 추출"""
        port_to_service = {
            '80-80': 'http', '443-443': 'https', '22-22': 'ssh',
            '21-21': 'ftp', '25-25': 'smtp', '53-53': 'dns'
        }
        
        if port_group in ['WEB_PORTS']:
            return ['http', 'https']
        elif port_group in ['DATABASE_PORTS']:
            return ['mysql', 'postgresql']
        elif port_group in ['MANAGEMENT_PORTS']:
            return ['ssh', 'snmp']
        
        return ['unknown']
    
    def _get_optimization_stats(self) -> Dict[str, Any]:
        """최적화 통계 생성"""
        original_count = len(self.policies)
        optimized_count = len(self.optimized_policies)
        
        return {
            'original_policy_count': original_count,
            'optimized_policy_count': optimized_count,
            'reduction_percentage': round((1 - optimized_count / original_count) * 100, 2) if original_count > 0 else 0,
            'address_groups_count': sum(len(groups) for groups in self.address_groups.values()),
            'port_groups_count': len(self.port_groups)
        }
