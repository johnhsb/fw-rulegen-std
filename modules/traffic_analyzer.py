#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
방화벽 정책 추천 시스템 - 트래픽 분석기
----------------------------------
로그 데이터를 분석하여 트래픽 패턴을 식별하고 시각화합니다.
"""

import gc
import ipaddress
import logging
import numpy as np
import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

# 포트-서비스 매핑
WELL_KNOWN_PORTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 443: "https", 110: "pop3", 143: "imap",
    161: "snmp", 123: "ntp", 389: "ldap", 636: "ldaps",
    # ... 추가 포트
}

class TrafficAnalyzer:
    """트래픽 패턴을 분석하고 정책을 추천하는 클래스"""
    
    def __init__(self, log_df, min_occurrences=1, eps=0.5, min_samples=2, max_data_points=30000):
        """
        초기화
        
        Args:
            log_df (DataFrame): 로그 데이터
            min_occurrences (int): 분석에 포함할 최소 발생 횟수
            eps (float): DBSCAN 클러스터링 거리 파라미터
            min_samples (int): DBSCAN 클러스터링 최소 샘플 수
            max_data_points (int): 클러스터링에 사용할 최대 데이터 포인트 수
        """
        self.log_df = log_df
        self.min_occurrences = min_occurrences
        self.eps = eps
        self.min_samples = min_samples
        self.max_data_points = max_data_points
        self.clustered_df = None
        self.policies = []
    
    def get_common_device_names(self, limit=10):
        """
        로그에서 가장 자주 등장하는 장비명 추출
        
        Args:
            limit (int): 반환할 최대 장비명 수
        
        Returns:
            list: (장비명, 카운트) 튜플의 리스트
        """
        if self.log_df is None or self.log_df.empty or 'device_name' not in self.log_df.columns:
            return []
        
        # 장비명 카운트
        device_counts = self.log_df['device_name'].value_counts()
        
        # 'unknown'인 장비명은 제외하고 상위 N개 반환
        if 'unknown' in device_counts:
            device_counts = device_counts.drop('unknown')
        
        # 상위 N개 장비명 반환 (장비명, 카운트) 튜플 형태로
        return [(name, count) for name, count in device_counts.head(limit).items()]
    
    def ip_to_int(self, ip):
        """
        IP 주소를 정수로 변환 (IPv4/IPv6 지원)
        
        Args:
            ip (str): IP 주소
        
        Returns:
            int: 정수로 변환된 IP 주소
        """
        if not ip:
            return 0

        try:
            if ':' in ip:  # IPv6
                # IPv6 주소의 처음 64비트만 사용 (네트워크 부분)
                ip_obj = ipaddress.IPv6Address(ip)
                return int(ip_obj) & ((1 << 64) - 1)
            else:  # IPv4
                return int(ipaddress.IPv4Address(ip))
        except Exception as e:
            logger.warning(f"IP 주소 변환 오류 {ip}: {e}")
            return 0
    
    def preprocess_data(self):
        """
        데이터 전처리 (IPv4/IPv6 지원)
        
        Returns:
            DataFrame: 전처리된 데이터
        """
        if self.log_df.empty:
            logger.error("분석할 데이터가 없습니다!")
            return self.log_df
        
        logger.info("분석을 위한 데이터 전처리 중...")
        
        # 필요한 열만 선택
        cols = ['source_ip', 'destination_ip', 'source_port', 'destination_port', 
                'protocol', 'source_zone', 'destination_zone', 'is_ipv6']
        
        # is_ipv6 열이 없는 경우 추가
        if 'is_ipv6' not in self.log_df.columns:
            self.log_df['is_ipv6'] = self.log_df['source_ip'].apply(lambda x: ':' in str(x))
        
        df = self.log_df[cols].copy()

        # ICMP 프로토콜 데이터 처리 - 포트 번호를 0으로 통일
        # ICMP와 ICMPv6는 포트 개념이 없으므로 포트 번호를 0으로 설정
        icmp_mask = (df['protocol'] == 'icmp') | (df['protocol'] == 'icmpv6')
        df.loc[icmp_mask, 'destination_port'] = 0
        df.loc[icmp_mask, 'source_port'] = 0
        
        # 중복 제거 및 나타난 횟수 계산
        df['occurrence'] = 1
        df = df.groupby(cols).sum().reset_index()
        
        # 최소 발생 횟수 필터링
        df = df[df['occurrence'] >= self.min_occurrences]
        
        # IPv4와 IPv6를 분리하여 처리
        ipv4_df = df[~df['is_ipv6']].copy()
        ipv6_df = df[df['is_ipv6']].copy()
        
        # IPv4 처리
        if not ipv4_df.empty:
            # IP 주소를 정수로 변환 (클러스터링을 위해)
            ipv4_df['src_ip_int'] = ipv4_df['source_ip'].apply(self.ip_to_int)
            ipv4_df['dst_ip_int'] = ipv4_df['destination_ip'].apply(self.ip_to_int)
            
            # IP 서브넷 정보 추가 (클러스터링 개선을 위해)
            ipv4_df['src_subnet'] = ipv4_df['source_ip'].apply(
                lambda x: str(ipaddress.IPv4Network(f"{x}/24", strict=False)))
            ipv4_df['dst_subnet'] = ipv4_df['destination_ip'].apply(
                lambda x: str(ipaddress.IPv4Network(f"{x}/24", strict=False)))
            
            # 서브넷을 정수로 변환
            ipv4_df['src_subnet_int'] = ipv4_df['src_subnet'].apply(
                lambda x: int(ipaddress.IPv4Network(x).network_address))
            ipv4_df['dst_subnet_int'] = ipv4_df['dst_subnet'].apply(
                lambda x: int(ipaddress.IPv4Network(x).network_address))
        
        # IPv6 처리
        if not ipv6_df.empty:
            # IPv6 주소를 64비트 정수로 변환 (네트워크 부분)
            ipv6_df['src_ip_int'] = ipv6_df['source_ip'].apply(self.ip_to_int)
            ipv6_df['dst_ip_int'] = ipv6_df['destination_ip'].apply(self.ip_to_int)
            
            # IPv6 서브넷 정보 추가 (/64 네트워크)
            ipv6_df['src_subnet'] = ipv6_df['source_ip'].apply(
                lambda x: str(ipaddress.IPv6Network(f"{x}/64", strict=False)))
            ipv6_df['dst_subnet'] = ipv6_df['destination_ip'].apply(
                lambda x: str(ipaddress.IPv6Network(f"{x}/64", strict=False)))
            
            # 서브넷을 정수로 변환 (상위 64비트만 사용)
            ipv6_df['src_subnet_int'] = ipv6_df['src_subnet'].apply(
                lambda x: int(ipaddress.IPv6Network(x).network_address) & ((1 << 64) - 1))
            ipv6_df['dst_subnet_int'] = ipv6_df['dst_subnet'].apply(
                lambda x: int(ipaddress.IPv6Network(x).network_address) & ((1 << 64) - 1))
        
        # IPv4와 IPv6 데이터 병합
        df = pd.concat([ipv4_df, ipv6_df])
        
        # 특정 IP 주소가 없는 경우 대비
        if 'src_ip_int' not in df.columns:
            df['src_ip_int'] = 0
        if 'dst_ip_int' not in df.columns:
            df['dst_ip_int'] = 0
        if 'src_subnet_int' not in df.columns:
            df['src_subnet_int'] = 0
        if 'dst_subnet_int' not in df.columns:
            df['dst_subnet_int'] = 0
        if 'src_subnet' not in df.columns:
            df['src_subnet'] = ''
        if 'dst_subnet' not in df.columns:
            df['dst_subnet'] = ''
        
        logger.info(f"전처리된 데이터: {len(df)} 고유 트래픽 패턴 " +
                   f"(IPv4: {len(ipv4_df)}, IPv6: {len(ipv6_df)})")
        return df
    
    def cluster_batch(self, data, batch_size=5000, is_ipv6=False, offset=0):
        """
        데이터 배치를 클러스터링하는 헬퍼 함수
        
        Args:
            data (DataFrame): 클러스터링할 데이터
            batch_size (int): 배치 크기
            is_ipv6 (bool): IPv6 데이터 여부
            offset (int): 클러스터 ID 오프셋
            
        Returns:
            DataFrame: 클러스터링된 데이터
        """
        # 데이터가 없으면 빈 데이터프레임 반환
        if data.empty:
            return data
            
        # 데이터가 배치 크기보다 크면 샘플링
        if len(data) > batch_size:
            logger.info(f"{len(data)} 레코드에서 {batch_size} 샘플 선택 (IPv6 = {is_ipv6})")
            
            # 트래픽 볼륨으로 정렬하고 상위 데이터 선택 (중요 트래픽 패턴 우선)
            sorted_data = data.sort_values('occurrence', ascending=False)
            
            # 상위 70%와 나머지 30%에서 랜덤 샘플링
            top_count = int(batch_size * 0.7)
            random_count = batch_size - top_count
            
            top_data = sorted_data.head(top_count)
            
            if len(sorted_data) > top_count and random_count > 0:
                random_data = sorted_data.iloc[top_count:].sample(
                    min(random_count, len(sorted_data) - top_count), 
                    random_state=42
                )
                batch_data = pd.concat([top_data, random_data])
            else:
                batch_data = top_data
        else:
            batch_data = data

        # ICMP 프로토콜 데이터와 기타 프로토콜 데이터 분리
        icmp_mask = (batch_data['protocol'] == 'icmp') | (batch_data['protocol'] == 'icmpv6')
        non_icmp_data = batch_data[~icmp_mask].copy()
        icmp_data = batch_data[icmp_mask].copy()
        
        # 클러스터링에 사용할 특성 (비 ICMP 데이터)
        if not non_icmp_data.empty:
            features_non_icmp = non_icmp_data[['src_subnet_int', 'dst_subnet_int', 'destination_port']]
            
            # 프로토콜 원-핫 인코딩
            protocol_dummies = pd.get_dummies(non_icmp_data['protocol'], prefix='proto')
            
            # 모든 특성 결합
            features_non_icmp = pd.concat([features_non_icmp, protocol_dummies], axis=1)
            
            # 데이터 스케일링
            scaler = StandardScaler()
            scaled_features_non_icmp = scaler.fit_transform(features_non_icmp)
        
            # DBSCAN 클러스터링
            logger.info(f"DBSCAN 클러스터링 실행: {len(non_icmp_data)} {'IPv6' if is_ipv6 else 'IPv4'} non-ICMP 레코드")
            clustering_non_icmp = DBSCAN(eps=self.eps, min_samples=self.min_samples).fit(scaled_features_non_icmp)
            
            # 클러스터 레이블 추가
            non_icmp_data['cluster'] = clustering_non_icmp.labels_
            
            # IPv6인 경우 오프셋 적용
            if is_ipv6 and offset > 0:
                non_icmp_data.loc[non_icmp_data['cluster'] != -1, 'cluster'] += offset
        else:
            non_icmp_data = pd.DataFrame(columns=batch_data.columns)
            non_icmp_data['cluster'] = []
        
        # ICMP 데이터 클러스터링 (포트 대신 IP 주소 기반으로)
        if not icmp_data.empty:
            features_icmp = icmp_data[['src_subnet_int', 'dst_subnet_int']]
            
            # 프로토콜 원-핫 인코딩
            icmp_protocol_dummies = pd.get_dummies(icmp_data['protocol'], prefix='proto')
            
            # 모든 특성 결합
            features_icmp = pd.concat([features_icmp, icmp_protocol_dummies], axis=1)
            
            # 데이터 스케일링
            scaler_icmp = StandardScaler()
            scaled_features_icmp = scaler_icmp.fit_transform(features_icmp)
        
            # DBSCAN 클러스터링 (ICMP 데이터는 다른 eps 값 고려)
            logger.info(f"DBSCAN 클러스터링 실행: {len(icmp_data)} {'IPv6' if is_ipv6 else 'IPv4'} ICMP 레코드")
            # ICMP는 소스와 대상 IP만 고려하므로 더 작은 eps 값 사용
            icmp_eps = self.eps * 0.8  
            clustering_icmp = DBSCAN(eps=icmp_eps, min_samples=self.min_samples).fit(scaled_features_icmp)
            
            # 클러스터 레이블 추가 (ICMP 클러스터는 특별한 번호로 시작)
            icmp_data['cluster'] = clustering_icmp.labels_
            
            # ICMP 클러스터는 다른 클러스터와 구분하기 위해 500 (IPv4) 또는 600 (IPv6) 오프셋 사용
            icmp_offset = 500 if not is_ipv6 else 600
            icmp_data.loc[icmp_data['cluster'] != -1, 'cluster'] += icmp_offset
            
            # IPv6인 경우 추가 오프셋 적용
            if is_ipv6 and offset > 0:
                icmp_data.loc[icmp_data['cluster'] != -1, 'cluster'] += offset
        else:
            icmp_data = pd.DataFrame(columns=batch_data.columns)
            icmp_data['cluster'] = []
            
        # 두 데이터셋 결합
        clustered_data = pd.concat([non_icmp_data, icmp_data])

        # 클러스터 통계
        clusters = clustered_data['cluster'].value_counts()
        cluster_count = len(clusters) - (1 if -1 in clusters else 0)
        logger.info(f"{'IPv6' if is_ipv6 else 'IPv4'} 클러스터: {cluster_count}")
        logger.info(f"{'IPv6' if is_ipv6 else 'IPv4'} 노이즈 포인트: {clusters.get(-1, 0)}")

        # 배치 데이터에 클러스터 컬럼 추가
        batch_data['cluster'] = -1

        # clustered_data의 인덱스 값을 사용하여 batch_data에 값 복사
        for idx in clustered_data.index:
            batch_data.loc[idx, 'cluster'] = clustered_data.loc[idx, 'cluster']

        
        # 배치 데이터만 처리했다면 나머지 데이터에 클러스터 할당
        if len(batch_data) < len(data):
            # 원본 데이터에 클러스터 컬럼 추가
            data['cluster'] = -1
            
            # 배치 데이터의 인덱스에 클러스터 값 복사
            data.loc[batch_data.index, 'cluster'] = batch_data['cluster']
            
            logger.info(f"{len(batch_data)} 레코드에 클러스터 할당. {len(data) - len(batch_data)} 레코드는 노이즈 포인트로 남음.")
            
            return data
        else:
            return batch_data
    
    def cluster_traffic_patterns(self):
        """
        트래픽 패턴 클러스터링 (IPv4/IPv6 지원) - 메모리 최적화 버전
        
        Returns:
            DataFrame: 클러스터 레이블이 포함된 데이터
        """
        df = self.preprocess_data()
        if df.empty:
            logger.warning("전처리 후 클러스터링할 데이터가 없습니다!")
            self.clustered_df = df  # 비어있는 df를 self.clustered_df에 할당
            return df
        
        logger.info("메모리 최적화를 통한 트래픽 패턴 클러스터링...")
        
        # IPv4와 IPv6 데이터 분리
        ipv4_df = df[~df['is_ipv6']].copy() if 'is_ipv6' in df.columns else df.copy()
        ipv6_df = df[df['is_ipv6']].copy() if 'is_ipv6' in df.columns else pd.DataFrame()
        
        # 클러스터 ID 오프셋 (IPv6 클러스터는 100부터 시작)
        ipv6_cluster_offset = 100
        
        # 배치 크기 계산 - 최대 데이터 포인트 기준
        ipv4_batch_size = min(self.max_data_points, len(ipv4_df))
        ipv6_batch_size = min(self.max_data_points, len(ipv6_df))
        
        # IPv4 데이터 클러스터링 - 배치 처리
        if not ipv4_df.empty:
            logger.info(f"IPv4 트래픽 패턴 클러스터링 ({len(ipv4_df)} 레코드)...")
            ipv4_df = self.cluster_batch(ipv4_df, ipv4_batch_size, is_ipv6=False)

        # 중간 메모리 정리
        try:
            gc.collect()
            logger.info("메모리 확보를 위한 가비지 컬렉션 수행")
        except Exception as e:
            logger.warning(f"가비지 컬렉션 중 오류: {e}")
        
        # IPv6 데이터 클러스터링 - 배치 처리
        if not ipv6_df.empty:
            logger.info(f"IPv6 트래픽 패턴 클러스터링 ({len(ipv6_df)} 레코드)...")
            ipv6_df = self.cluster_batch(ipv6_df, ipv6_batch_size, is_ipv6=True, offset=ipv6_cluster_offset)
        
        # 결과 병합
        df = pd.concat([ipv4_df, ipv6_df])
        
        # 클러스터 통계 (전체)
        clusters = df['cluster'].value_counts()
        total_clusters = len(clusters) - (1 if -1 in clusters else 0)
        logger.info(f"총 클러스터: {total_clusters}, 노이즈 포인트: {clusters.get(-1, 0)}")
        
        self.clustered_df = df
        return df
    
    def optimize_ip_ranges(self, ip_list):
        """
        IP 주소 목록을 최적화된 CIDR 블록으로 변환 (IPv4/IPv6 지원)

        Args:
            ip_list (list): IP 주소 목록
            
        Returns:
            list: 최적화된 CIDR 블록 목록
        """
        if not ip_list:
            return []
            
        # 단일 IP인 경우
        if len(ip_list) == 1:
            ip = ip_list[0]
            prefix = '/128' if ':' in ip else '/32'
            return [f"{ip}{prefix}"]
        
        # IPv4와 IPv6 주소 분리
        ipv4_list = []
        ipv6_list = []
        
        for ip in ip_list:
            if ':' in ip:
                ipv6_list.append(ip)
            else:
                ipv4_list.append(ip)
        
        cidr_blocks = []
        
        # IPv4 주소 처리
        if ipv4_list:
            try:
                # 각 IP를 IPv4Address 객체로 변환
                ip_objects = [ipaddress.IPv4Address(ip) for ip in ipv4_list]
                
                # IP 주소 정렬
                ip_objects.sort()
                
                # 정렬된 IP 주소를 /32 네트워크로 변환
                networks = [ipaddress.IPv4Network(f"{ip}/32", strict=False) for ip in ip_objects]
                
                # 네트워크 병합
                collapsed = list(ipaddress.collapse_addresses(networks))
                cidr_blocks.extend([str(cidr) for cidr in collapsed])
            except Exception as e:
                logger.warning(f"IPv4 주소 범위 최적화 오류: {e}")
                # 실패 시 개별 IP 반환
                cidr_blocks.extend([f"{ip}/32" for ip in ipv4_list])

        # IPv6 주소 처리
        if ipv6_list:
            try:
                # 각 IP를 IPv6Address 객체로 변환
                ip_objects = [ipaddress.IPv6Address(ip) for ip in ipv6_list]
                
                # IP 주소 정렬
                ip_objects.sort()
                
                # 정렬된 IP 주소를 /128 네트워크로 변환
                networks = [ipaddress.IPv6Network(f"{ip}/128", strict=False) for ip in ip_objects]
                
                # /64 네트워크로 그룹화 시도
                try:
                    # /64 네트워크로 그룹화
                    supernets = []
                    for network in networks:
                        # /64 네트워크 생성
                        supernet = ipaddress.IPv6Network(f"{network.network_address}/64", strict=False)
                        if supernet not in supernets:
                            supernets.append(supernet)
                    
                    # 중복 제거 및 병합
                    collapsed = list(ipaddress.collapse_addresses(supernets))
                    cidr_blocks.extend([str(cidr) for cidr in collapsed])
                except:
                    # 기본 병합 시도
                    collapsed = list(ipaddress.collapse_addresses(networks))
                    cidr_blocks.extend([str(cidr) for cidr in collapsed])
            except Exception as e:
                logger.warning(f"IPv6 주소 처리 오류: {e}")
                # 오류 발생 시 개별 IP 반환
                cidr_blocks.extend([f"{ip}/128" for ip in ipv6_list])

        return cidr_blocks

    def analyze_top_traffic_patterns(self, top_n=30):
        """
        트래픽에서 상위 트래픽 패턴을 분석하여 출력
        
        동일한 출발지IP블럭(/24)-목적지IP(/32)-프로토콜-목적지포트 별로 카운트
        
        Args:
            top_n (int): 출력할 상위 패턴 수
        
        Returns:
            DataFrame: 상위 트래픽 패턴
        """
        if self.clustered_df is None:
            self.cluster_traffic_patterns()
        
        if self.clustered_df.empty:
            logger.error("분석할 데이터가 없습니다!")
            return None
        
        logger.info(f"상위 {top_n} 트래픽 패턴 분석 중...")
        
        # IPv4/IPv6 데이터 모두 처리
        result_dfs = []
        
        for is_ipv6 in [False, True]:
            # 해당 IP 버전의 데이터 필터링
            if 'is_ipv6' in self.clustered_df.columns:
                version_df = self.clustered_df[self.clustered_df['is_ipv6'] == is_ipv6].copy()
            else:
                # is_ipv6 컬럼이 없는 경우 IP 주소 형식으로 판단
                version_df = self.clustered_df[self.clustered_df['source_ip'].apply(
                    lambda x: ':' in str(x)) == is_ipv6].copy()
            
            if version_df.empty:
                continue
            
            # 출발지 IP를 서브넷으로 그룹화
            if 'src_subnet' not in version_df.columns:
                if is_ipv6:
                    # IPv6는 /64 서브넷으로 그룹화
                    version_df['src_subnet'] = version_df['source_ip'].apply(
                        lambda x: str(ipaddress.IPv6Network(f"{x}/64", strict=False)))
                else:
                    # IPv4는 /24 서브넷으로 그룹화
                    version_df['src_subnet'] = version_df['source_ip'].apply(
                        lambda x: str(ipaddress.IPv4Network(f"{x}/24", strict=False)))
            
            # 출발지 서브넷(/24) + 목적지 IP(/32) + 프로토콜 + 목적지 포트로 그룹화하여 트래픽 볼륨 계산
            agg_cols = ['src_subnet', 'destination_ip', 'protocol', 'destination_port']
            traffic_grouped = version_df.groupby(agg_cols).agg({
                'occurrence': 'sum',
                'source_ip': lambda x: list(set(x))  # 고유 소스 IP 목록
            }).reset_index()
            
            # 트래픽 볼륨으로 정렬
            traffic_grouped.sort_values('occurrence', ascending=False, inplace=True)
            
            # 상위 N개만 선택 (각 IP 버전별로)
            top_traffic = traffic_grouped.head(top_n)
            
            # 전체 트래픽 대비 비율 계산
            total_traffic = traffic_grouped['occurrence'].sum()
            top_traffic['percentage'] = (top_traffic['occurrence'] / max(total_traffic, 1) * 100).round(2)
            
            # 소스 IP 개수 계산
            top_traffic['src_ip_count'] = top_traffic['source_ip'].apply(len)
            
            # 포트/프로토콜 정보 포맷팅
            top_traffic['port_info'] = top_traffic.apply(
                lambda row: f"{row['destination_port']}({row['protocol']})", axis=1)
            
            # 필요한 컬럼만 선택
            result_df = top_traffic[['src_subnet', 'destination_ip', 'protocol', 'destination_port', 
                                    'port_info', 'occurrence', 'percentage', 'src_ip_count']]
            
            # IP 버전 표시 추가
            result_df['is_ipv6'] = is_ipv6
            
            result_dfs.append(result_df)
        
        # 결과 데이터프레임 합치기
        if not result_dfs:
            return pd.DataFrame()
        
        return pd.concat(result_dfs)


    def generate_descriptive_policy_name(self, dst_networks, port_ranges, protocols, service_names, cluster_id, is_ipv6=False):
        """
        클러스터 정보에 기반한 설명적인 정책 이름 생성
        
        Args:
            dst_networks (list): 대상 네트워크 목록
            port_ranges (list): 포트 범위 목록
            protocols (list): 프로토콜 목록
            service_names (list): 서비스 이름 목록
            cluster_id (int): 클러스터 ID
            is_ipv6 (bool): IPv6 정책 여부
            
        Returns:
            str: 생성된 정책 이름
        """
        # IP 버전 접두사
        ip_version = "IPv6-" if is_ipv6 else ""
        
        # 정책 접두사: 서비스 또는 프로토콜 기반
        if service_names and service_names[0] != "unknown":
            prefix = f"{ip_version}{service_names[0].upper()}"
        elif protocols:
            prefix = f"{ip_version}{protocols[0].upper()}"
        else:
            prefix = f"{ip_version}Policy"
        
        # 정책 대상 정보
        if dst_networks:
            # 적절한 CIDR 표기로 변환
            cidr = dst_networks[0].split('/')
            if len(cidr) > 1:
                net_desc = cidr[0]
            else:
                net_desc = dst_networks[0]
                
            # IP 주소 단축 (가독성을 위해)
            parts = net_desc.split('.')
            if len(parts) == 4:  # IPv4
                net_desc = f"{parts[0]}.{parts[1]}"
            elif ':' in net_desc:  # IPv6
                # IPv6 주소는 접두사 4자만 사용
                net_desc = net_desc.split(':')[0]
        else:
            net_desc = "Any"
        
        # 포트 정보
        if port_ranges:
            port_desc = f"p{port_ranges[0].split('-')[0]}"
        else:
            port_desc = "pAny"
        
        # 최종 정책 이름
        policy_name = f"{prefix}-{net_desc}-{port_desc}-C{cluster_id}"
        
        # 특수 문자 제거 (정책 이름에 사용할 수 없는 문자)
        policy_name = policy_name.replace('/', '-').replace(':', '-')
        
        return policy_name
    
    def generate_policy_recommendations(self):
        """
        클러스터링된 트래픽 패턴을 기반으로 정책 추천 생성
        
        Returns:
            list: 추천 정책 목록 (딕셔너리 형태)
        """
        if self.clustered_df is None or self.clustered_df.empty:
            logger.warning("정책 추천을 위한 데이터가 없습니다!")
            return []
        
        logger.info("정책 추천 생성 중...")
        
        # 클러스터 ID 목록 (-1은 노이즈 포인트이므로 제외)
        clusters = sorted(list(set(self.clustered_df['cluster'].values)))
        clusters = [c for c in clusters if c != -1]
        
        recommendations = []
        
        # 각 클러스터에 대한 정책 생성
        for cluster_id in clusters:
            # 클러스터에 속한 트래픽 패턴 찾기
            cluster_data = self.clustered_df[self.clustered_df['cluster'] == cluster_id]
            
            if cluster_data.empty:
                continue
            
            # IPv6 정책 여부 확인
            is_ipv6 = cluster_data['is_ipv6'].iloc[0] if 'is_ipv6' in cluster_data.columns else False
            
            # 소스 IP, 목적지 IP, 포트, 프로토콜 수집
            src_ips = list(cluster_data['source_ip'].unique())
            dst_ips = list(cluster_data['destination_ip'].unique())
            ports = sorted(list(cluster_data['destination_port'].unique()))
            protocols = sorted(list(cluster_data['protocol'].unique()))
            
            # 소스 존, 목적지 존 수집
            src_zones = sorted(list(cluster_data['source_zone'].unique()))
            dst_zones = sorted(list(cluster_data['destination_zone'].unique()))
            
            # 서비스 이름 수집
            service_names = []
            for port in ports:
                if port in WELL_KNOWN_PORTS:
                    service_name = WELL_KNOWN_PORTS[port]
                    if service_name not in service_names:
                        service_names.append(service_name)
            
            # 서비스 이름이 없으면 프로토콜 이름 사용
            if not service_names:
                service_names = protocols
            
            # 포트 범위 최적화
            port_ranges = self.optimize_port_ranges(ports)
            
            # IP 범위 최적화
            src_networks = self.optimize_ip_ranges(src_ips)
            dst_networks = self.optimize_ip_ranges(dst_ips)
            
            # 정책 이름 생성
            policy_name = self.generate_descriptive_policy_name(
                dst_networks, port_ranges, protocols, service_names, cluster_id, is_ipv6)
            
            # 정책 정보 생성
            policy = {
                'name': policy_name,
                'id': f"C{cluster_id}",
                'src_networks': src_networks,
                'dst_networks': dst_networks,
                'port_ranges': port_ranges,
                'protocols': protocols,
                'service_names': service_names,
                'src_zones': src_zones,
                'dst_zones': dst_zones,
                'is_ipv6': is_ipv6,
                'traffic_count': cluster_data['occurrence'].sum()
            }
            
            recommendations.append(policy)
        
        # 트래픽 양에 따라 정책 정렬
        recommendations.sort(key=lambda x: x['traffic_count'], reverse=True)
        
        self.policies = recommendations
        
        logger.info(f"{len(recommendations)}개의 정책 추천 생성 완료")
        return recommendations

    def optimize_port_ranges(self, ports):
        """
        포트 목록을 최적화된 포트 범위로 변환
        
        Args:
            ports (list): 포트 번호 목록
            
        Returns:
            list: 최적화된 포트 범위 목록 (예: ["80-80", "8080-8090"])
        """
        if not ports:
            return []
        
        # 정렬 및 중복 제거
        sorted_ports = sorted(list(set(ports)))
        
        ranges = []
        start = sorted_ports[0]
        end = start
        
        for i in range(1, len(sorted_ports)):
            current = sorted_ports[i]
            
            # 연속된 포트인 경우
            if current == end + 1:
                end = current
            else:
                # 이전 범위 저장하고 새 범위 시작
                ranges.append(f"{start}-{end}")
                start = current
                end = current
        
        # 마지막 범위 추가
        ranges.append(f"{start}-{end}")
        
        return ranges
    
    def visualize_traffic_sankey(self, output_prefix='traffic_sankey'):
        """
        트래픽 흐름을 Sankey 다이어그램으로 시각화 (IPv4/IPv6 지원)
        
        출발지IP(/32)와 목적지IP(/32)간의 연결구조만 표현
        둘 간의 연결선 굵기는 동일한 목적지 포트를 가진 로그 수에 비례
        
        Args:
            output_prefix (str): 출력 파일 접두사
            
        Returns:
            dict: 생성된 파일 정보
        """
        import plotly.graph_objects as go
        import plotly.io as pio
        
        if self.clustered_df is None or self.clustered_df.empty:
            logger.warning("시각화할 데이터가 없습니다!")
            return {}
        
        logger.info("Sankey 다이어그램 생성 중...")
        
        # 결과 파일 정보
        file_info = {}
        
        # IPv4/IPv6 분리
        ipv4_df = self.clustered_df[~self.clustered_df['is_ipv6']].copy() if 'is_ipv6' in self.clustered_df.columns else self.clustered_df.copy()
        ipv6_df = self.clustered_df[self.clustered_df['is_ipv6']].copy() if 'is_ipv6' in self.clustered_df.columns else pd.DataFrame()
        
        # Sankey 다이어그램 생성 함수
        def create_sankey_diagram(df, title, output_file, is_ipv6=False):
            if df.empty:
                return None
                
            logger.info(f"{title} 생성 중...")
            
            # 소스와 대상 IP, 포트, 프로토콜 기준으로 트래픽 집계
            flow_df = df.groupby(['source_ip', 'destination_ip', 'destination_port', 'protocol'])['occurrence'].sum().reset_index()
            
            # 고유한 소스와 대상 IP 목록 생성
            source_ips = list(flow_df['source_ip'].unique())
            dest_ips = list(flow_df['destination_ip'].unique())
            
            # 네트워크 크기가 너무 클 경우 최상위 트래픽만 사용
            max_nodes = 30  # 최대 노드 수
            max_edges = 50  # 최대 엣지 수
            
            if len(source_ips) > max_nodes or len(dest_ips) > max_nodes:
                # 트래픽 양 기준으로 정렬
                flow_df = flow_df.sort_values('occurrence', ascending=False)
                
                # 상위 트래픽만 선택
                flow_df = flow_df.head(max_edges)
                
                # 사용된 소스 및 대상 IP 다시 계산
                source_ips = list(flow_df['source_ip'].unique())
                dest_ips = list(flow_df['destination_ip'].unique())
            
            # 모든 노드 (소스 IP + 대상 IP) 생성
            all_nodes = source_ips + dest_ips
            # 중복 제거
            all_nodes = sorted(list(set(all_nodes)))
            
            # 노드 인덱스 매핑 생성
            node_indices = {node: i for i, node in enumerate(all_nodes)}
            
            # Sankey 다이어그램 데이터 생성
            source_indices = []
            target_indices = []
            values = []
            link_labels = []
            
            for _, row in flow_df.iterrows():
                src_idx = node_indices[row['source_ip']]
                dst_idx = node_indices[row['destination_ip']]
                source_indices.append(src_idx)
                target_indices.append(dst_idx)
                values.append(row['occurrence'])
                
                # 포트와 프로토콜 레이블 생성
                port = row['destination_port']
                protocol = row['protocol']
                
                # Well-known 포트인 경우 서비스 이름 표시
                if port in WELL_KNOWN_PORTS:
                    port_label = f"{WELL_KNOWN_PORTS[port]} ({port})"
                else:
                    port_label = str(port)
                
                link_label = f"{protocol.upper()}/{port_label}"
                link_labels.append(link_label)
            
            # 노드 색상 설정
            node_colors = []
            for node in all_nodes:
                if node in source_ips and node in dest_ips:
                    # 소스와 대상 모두인 경우 보라색
                    node_colors.append('rgba(128, 0, 128, 0.8)')
                elif node in source_ips:
                    # 소스만인 경우 파란색
                    node_colors.append('rgba(31, 119, 180, 0.8)')
                else:
                    # 대상만인 경우 빨간색
                    node_colors.append('rgba(214, 39, 40, 0.8)')
            
            # Sankey 다이어그램 생성
            fig = go.Figure(data=[go.Sankey(
                node=dict(
                    pad=15,
                    thickness=20,
                    line=dict(color="black", width=0.5),
                    label=all_nodes,
                    color=node_colors
                ),
                link=dict(
                    source=source_indices,
                    target=target_indices,
                    value=values,
                    label=link_labels,
                    hovertemplate='%{source.label} → %{target.label}<br>' +
                                  '프로토콜/포트: %{label}<br>' +
                                  '트래픽: %{value}<extra></extra>'
                )
            )])
            
            # 레이아웃 설정
            fig.update_layout(
                title_text=title,
                font=dict(size=12),
                autosize=True,
                height=800,
                margin=dict(l=25, r=25, b=25, t=50, pad=4)
            )
            
            # HTML 파일로 저장
            pio.write_html(fig, output_file)
            
            return output_file
        
        # IPv4 Sankey 다이어그램
        if not ipv4_df.empty:
            ipv4_html_file = f"{output_prefix}_ipv4.html"
            ipv4_result = create_sankey_diagram(
                ipv4_df, 
                "IPv4 트래픽 흐름 (소스 → 대상)", 
                ipv4_html_file,
                is_ipv6=False
            )
            if ipv4_result:
                file_info['ipv4'] = ipv4_result
                logger.info(f"IPv4 Sankey 다이어그램 저장 완료: {ipv4_result}")
        
        # IPv6 Sankey 다이어그램
        if not ipv6_df.empty:
            ipv6_html_file = f"{output_prefix}_ipv6.html"
            ipv6_result = create_sankey_diagram(
                ipv6_df, 
                "IPv6 트래픽 흐름 (소스 → 대상)", 
                ipv6_html_file,
                is_ipv6=True
            )
            if ipv6_result:
                file_info['ipv6'] = ipv6_result
                logger.info(f"IPv6 Sankey 다이어그램 저장 완료: {ipv6_result}")
        
        return file_info

    def visualize_traffic_patterns_3d_interactive(self, output_prefix='traffic_3d'):
        """
        트래픽 패턴을 3D 인터랙티브 시각화 (IPv4/IPv6 지원)
        """
        import plotly.graph_objects as go
        import plotly.io as pio
        
        if self.clustered_df is None or self.clustered_df.empty:
            logger.warning("시각화할 데이터가 없습니다!")
            return {}
        
        logger.info("3D 인터랙티브 시각화 생성 중...")
        
        # 결과 파일 정보
        file_info = {}
        
        # IPv4/IPv6 분리
        ipv4_df = self.clustered_df[~self.clustered_df['is_ipv6']].copy() if 'is_ipv6' in self.clustered_df.columns else self.clustered_df.copy()
        ipv6_df = self.clustered_df[self.clustered_df['is_ipv6']].copy() if 'is_ipv6' in self.clustered_df.columns else pd.DataFrame()
        
        # IPv4 3D 시각화
        if not ipv4_df.empty:
            logger.info("IPv4 3D 시각화 생성...")
            
            # 시각화할 샘플 선택 (최대 5000개)
            sample_size = min(5000, len(ipv4_df))
            
            # 트래픽 양이 많은 순으로 정렬하고 상위 80% 데이터와 나머지 20%에서 랜덤 샘플링
            sorted_df = ipv4_df.sort_values('occurrence', ascending=False)
            
            top_count = int(sample_size * 0.8)
            random_count = sample_size - top_count
            
            top_data = sorted_df.head(top_count)
            
            if len(sorted_df) > top_count and random_count > 0:
                remaining_data = sorted_df.iloc[top_count:]
                random_data = remaining_data.sample(
                    min(random_count, len(remaining_data)),
                    random_state=42
                )
                sample_df = pd.concat([top_data, random_data])
            else:
                sample_df = top_data
            
            # 3D 시각화 데이터 준비
            x = sample_df['source_ip'].values
            y = sample_df['destination_ip'].values
            z = sample_df['destination_port'].astype(int).values
            
            # 클러스터에 따른 색상 지정
            clusters = sample_df['cluster'].values
            unique_clusters = sorted(list(set(clusters)))
            
            # 각 클러스터의 트래픽 양 계산
            cluster_traffic = {}
            for cluster in unique_clusters:
                cluster_mask = sample_df['cluster'] == cluster
                cluster_traffic[cluster] = sample_df[cluster_mask]['occurrence'].sum()
            
            # 전체 트래픽 양의 최대/최소값
            traffic_values = list(cluster_traffic.values())
            if traffic_values:
                max_traffic = max(sample_df['occurrence'])
                min_traffic = min(sample_df['occurrence'])
            else:
                max_traffic = 1
                min_traffic = 1
            
            # 플롯 데이터
            data = []
            
            # 클러스터별로 표시
            for cluster in unique_clusters:
                if cluster == -1:
                    continue  # 노이즈 포인트 제외
                
                mask = clusters == cluster
                cluster_data = sample_df[mask]
                text = []
                
                # 각 포인트의 크기 계산 (트래픽 양에 비례)
                point_sizes = []
                for i, (idx, row) in enumerate(cluster_data.iterrows()):
                    # 개별 포인트의 트래픽 양에 따른 크기 계산
                    occurrence = row['occurrence']
                    # 크기를 3-20 사이로 정규화
                    if max_traffic > min_traffic:
                        normalized_size = 3 + 17 * (occurrence - min_traffic) / (max_traffic - min_traffic)
                    else:
                        normalized_size = 10
                    point_sizes.append(normalized_size)
                    
                    text.append(
                        f"출발지: {row['source_ip']}<br>" +
                        f"목적지: {row['destination_ip']}<br>" +
                        f"포트: {row['destination_port']}<br>" +
                        f"프로토콜: {row['protocol']}<br>" +
                        f"클러스터: {cluster}<br>" +
                        f"트래픽: {occurrence}"
                    )
                
                # 클러스터의 총 트래픽 양
                total_cluster_traffic = cluster_traffic[cluster]
                
                # 클러스터별 산점도 추가
                scatter = go.Scatter3d(
                    x=cluster_data['source_ip'].values,
                    y=cluster_data['destination_ip'].values,
                    z=cluster_data['destination_port'].astype(int).values,
                    mode='markers',
                    marker=dict(
                        size=point_sizes,  # 동적 크기 적용
                        opacity=0.8,
                        line=dict(width=0.5, color='#1f1f1f')  # 다크모드에 맞는 테두리 색상
                    ),
                    text=text,
                    name=f"클러스터 {cluster} (트래픽: {total_cluster_traffic})",
                    hovertemplate='%{text}<extra></extra>'
                )
                
                data.append(scatter)
            
            # 노이즈 포인트 표시
            noise_mask = clusters == -1
            if any(noise_mask):
                noise_data = sample_df[noise_mask]
                noise_text = []
                noise_sizes = []
                
                for idx, row in noise_data.iterrows():
                    occurrence = row['occurrence']
                    # 노이즈 포인트는 더 작게 표시
                    if max_traffic > min_traffic:
                        normalized_size = 2 + 8 * (occurrence - min_traffic) / (max_traffic - min_traffic)
                    else:
                        normalized_size = 5
                    noise_sizes.append(normalized_size)
                    
                    noise_text.append(
                        f"출발지: {row['source_ip']}<br>" +
                        f"목적지: {row['destination_ip']}<br>" +
                        f"포트: {row['destination_port']}<br>" +
                        f"프로토콜: {row['protocol']}<br>" +
                        f"클러스터: 노이즈<br>" +
                        f"트래픽: {occurrence}"
                    )
                
                scatter = go.Scatter3d(
                    x=noise_data['source_ip'].values,
                    y=noise_data['destination_ip'].values,
                    z=noise_data['destination_port'].astype(int).values,
                    mode='markers',
                    marker=dict(
                        size=noise_sizes,  # 동적 크기 적용
                        color='#636363',  # 다크모드에 맞는 회색
                        opacity=0.6
                    ),
                    text=noise_text,
                    name="노이즈 포인트",
                    hovertemplate='%{text}<extra></extra>'
                )
                
                data.append(scatter)
            
            # 3D 그래프 생성 - 다크 테마 적용
            layout = go.Layout(
                title=dict(
                    text='IPv4 트래픽 패턴 3D 시각화 (크기는 트래픽 양에 비례)',
                    font=dict(color='#f2f2f2')
                ),
                template='plotly_dark',  # 다크 테마 적용
                scene=dict(
                    xaxis=dict(
                        title='출발지 IP',
                        backgroundcolor="#1f1f1f",
                        gridcolor='#444',
                        showbackground=True,
                        zerolinecolor='#444',
                    ),
                    yaxis=dict(
                        title='목적지 IP',
                        backgroundcolor="#1f1f1f",
                        gridcolor='#444',
                        showbackground=True,
                        zerolinecolor='#444',
                    ),
                    zaxis=dict(
                        title='목적지 포트',
                        backgroundcolor="#1f1f1f",
                        gridcolor='#444',
                        showbackground=True,
                        zerolinecolor='#444',
                        tickformat='d',
                    ),
                    camera=dict(
                        eye=dict(x=1.5, y=1.5, z=1.5)
                    ),
                    bgcolor='#111111'
                ),
                paper_bgcolor='#111111',
                plot_bgcolor='#111111',
                margin=dict(l=0, r=0, b=0, t=40),  # 업로드된 파일과 동일하게 설정
                showlegend=True,
                legend=dict(
                    font=dict(color='#f2f2f2', size=12),
                    title=dict(text='클러스터', font=dict(color='#f2f2f2')),
                    x=0.01,  # 왼쪽에 위치
                    y=0.99,  # 위쪽에 위치
                    bordercolor='#444',
                    borderwidth=1,
                    bgcolor='rgba(30, 31, 40, 0.85)'  # 업로드된 파일과 동일한 배경색
                ),
                font=dict(color='#f2f2f2')
            )
            
            fig = go.Figure(data=data, layout=layout)
            
            # 파일 저장
            ipv4_html_file = f"{output_prefix}_ipv4.html"
            pio.write_html(fig, ipv4_html_file)
            file_info['ipv4'] = ipv4_html_file
            
            logger.info(f"IPv4 3D 시각화 저장 완료: {ipv4_html_file}")
        
        # IPv6 3D 시각화
        if not ipv6_df.empty:
            logger.info("IPv6 3D 시각화 생성...")
            
            # 시각화할 샘플 선택 (최대 5000개)
            sample_size = min(5000, len(ipv6_df))
            
            # 트래픽 양이 많은 순으로 정렬하고 상위 80% 데이터와 나머지 20%에서 랜덤 샘플링
            sorted_df = ipv6_df.sort_values('occurrence', ascending=False)
            
            top_count = int(sample_size * 0.8)
            random_count = sample_size - top_count
            
            top_data = sorted_df.head(top_count)
            
            if len(sorted_df) > top_count and random_count > 0:
                remaining_data = sorted_df.iloc[top_count:]
                random_data = remaining_data.sample(
                    min(random_count, len(remaining_data)),
                    random_state=42
                )
                sample_df = pd.concat([top_data, random_data])
            else:
                sample_df = top_data
            
            # 3D 시각화 데이터 준비
            x = sample_df['source_ip'].values
            y = sample_df['destination_ip'].values
            z = sample_df['destination_port'].astype(int).values
            
            # 클러스터에 따른 색상 지정
            clusters = sample_df['cluster'].values
            unique_clusters = sorted(list(set(clusters)))
            
            # 각 클러스터의 트래픽 양 계산
            cluster_traffic = {}
            for cluster in unique_clusters:
                cluster_mask = sample_df['cluster'] == cluster
                cluster_traffic[cluster] = sample_df[cluster_mask]['occurrence'].sum()
            
            # 전체 트래픽 양의 최대/최소값
            traffic_values = list(cluster_traffic.values())
            if traffic_values:
                max_traffic = max(sample_df['occurrence'])
                min_traffic = min(sample_df['occurrence'])
            else:
                max_traffic = 1
                min_traffic = 1
            
            # 플롯 데이터
            data = []
            
            # 클러스터별로 표시
            for cluster in unique_clusters:
                if cluster == -1:
                    continue  # 노이즈 포인트 제외
                
                mask = clusters == cluster
                cluster_data = sample_df[mask]
                text = []
                
                # 각 포인트의 크기 계산 (트래픽 양에 비례)
                point_sizes = []
                for i, (idx, row) in enumerate(cluster_data.iterrows()):
                    # 개별 포인트의 트래픽 양에 따른 크기 계산
                    occurrence = row['occurrence']
                    # 크기를 3-20 사이로 정규화
                    if max_traffic > min_traffic:
                        normalized_size = 3 + 17 * (occurrence - min_traffic) / (max_traffic - min_traffic)
                    else:
                        normalized_size = 10
                    point_sizes.append(normalized_size)
                    
                    text.append(
                        f"출발지: {row['source_ip']}<br>" +
                        f"목적지: {row['destination_ip']}<br>" +
                        f"포트: {row['destination_port']}<br>" +
                        f"프로토콜: {row['protocol']}<br>" +
                        f"클러스터: {cluster}<br>" +
                        f"트래픽: {occurrence}"
                    )
                
                # 클러스터의 총 트래픽 양
                total_cluster_traffic = cluster_traffic[cluster]
                
                # 클러스터별 산점도 추가
                scatter = go.Scatter3d(
                    x=cluster_data['source_ip'].values,
                    y=cluster_data['destination_ip'].values,
                    z=cluster_data['destination_port'].astype(int).values,
                    mode='markers',
                    marker=dict(
                        size=point_sizes,  # 동적 크기 적용
                        opacity=0.8,
                        line=dict(width=0.5, color='#1f1f1f')  # 다크모드에 맞는 테두리 색상
                    ),
                    text=text,
                    name=f"클러스터 {cluster} (트래픽: {total_cluster_traffic})",
                    hovertemplate='%{text}<extra></extra>'
                )
                
                data.append(scatter)
            
            # 노이즈 포인트 표시
            noise_mask = clusters == -1
            if any(noise_mask):
                noise_data = sample_df[noise_mask]
                noise_text = []
                noise_sizes = []
                
                for idx, row in noise_data.iterrows():
                    occurrence = row['occurrence']
                    # 노이즈 포인트는 더 작게 표시
                    if max_traffic > min_traffic:
                        normalized_size = 2 + 8 * (occurrence - min_traffic) / (max_traffic - min_traffic)
                    else:
                        normalized_size = 5
                    noise_sizes.append(normalized_size)
                    
                    noise_text.append(
                        f"출발지: {row['source_ip']}<br>" +
                        f"목적지: {row['destination_ip']}<br>" +
                        f"포트: {row['destination_port']}<br>" +
                        f"프로토콜: {row['protocol']}<br>" +
                        f"클러스터: 노이즈<br>" +
                        f"트래픽: {occurrence}"
                    )
                
                scatter = go.Scatter3d(
                    x=noise_data['source_ip'].values,
                    y=noise_data['destination_ip'].values,
                    z=noise_data['destination_port'].astype(int).values,
                    mode='markers',
                    marker=dict(
                        size=noise_sizes,  # 동적 크기 적용
                        color='#636363',  # 다크모드에 맞는 회색
                        opacity=0.6
                    ),
                    text=noise_text,
                    name="노이즈 포인트",
                    hovertemplate='%{text}<extra></extra>'
                )
                
                data.append(scatter)
            
            # 3D 그래프 생성 - 다크 테마 적용
            layout = go.Layout(
                title=dict(
                    text='IPv6 트래픽 패턴 3D 시각화 (크기는 트래픽 양에 비례)',
                    font=dict(color='#f2f2f2')
                ),
                template='plotly_dark',  # 다크 테마 적용
                scene=dict(
                    xaxis=dict(
                        title='출발지 IP',
                        backgroundcolor="#1f1f1f",
                        gridcolor='#444',
                        showbackground=True,
                        zerolinecolor='#444',
                    ),
                    yaxis=dict(
                        title='목적지 IP',
                        backgroundcolor="#1f1f1f",
                        gridcolor='#444',
                        showbackground=True,
                        zerolinecolor='#444',
                    ),
                    zaxis=dict(
                        title='목적지 포트',
                        backgroundcolor="#1f1f1f",
                        gridcolor='#444',
                        showbackground=True,
                        zerolinecolor='#444',
                        tickformat='d',
                    ),
                    camera=dict(
                        eye=dict(x=1.5, y=1.5, z=1.5)
                    ),
                    bgcolor='#111111'
                ),
                paper_bgcolor='#111111',
                plot_bgcolor='#111111',
                margin=dict(l=0, r=0, b=0, t=40),  # 업로드된 파일과 동일하게 설정
                showlegend=True,
                legend=dict(
                    font=dict(color='#f2f2f2', size=12),
                    title=dict(text='클러스터', font=dict(color='#f2f2f2')),
                    x=0.01,  # 왼쪽에 위치
                    y=0.99,  # 위쪽에 위치
                    bordercolor='#444',
                    borderwidth=1,
                    bgcolor='rgba(30, 31, 40, 0.85)'  # 업로드된 파일과 동일한 배경색
                ),
                font=dict(color='#f2f2f2')
            )
            
            fig = go.Figure(data=data, layout=layout)
            
            # 파일 저장
            ipv6_html_file = f"{output_prefix}_ipv6.html"
            pio.write_html(fig, ipv6_html_file)
            file_info['ipv6'] = ipv6_html_file
            
            logger.info(f"IPv6 3D 시각화 저장 완료: {ipv6_html_file}")
        
        return file_info
