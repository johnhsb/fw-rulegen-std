#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
방화벽 정책 추천 시스템 - 로그 파서
----------------------------------
방화벽 로그 파일을 파싱하여 분석 가능한 형태로 변환합니다.
"""

import os
import re
import ipaddress
import logging
import pandas as pd
from datetime import datetime

logger = logging.getLogger(__name__)

# 주니퍼 syslog 패턴 정규식
JUNIPER_SESSION_PATTERN = re.compile(
    r'.*RT_FLOW: RT_FLOW_SESSION_(?:CREATE|CLOSE):' # 세션 시작/종료
    r'(?:\s+session\s+([a-zA-Z\s]+)):?\s*' # 세션 종료 원인 (선택적)
    r'([\d\.a-fA-F:]+)/(\d+)->([\d\.a-fA-F:]+)/(\d+)' # 첫 번째 IP 주소/포트 쌍
    r'\s+0x\d+\s+([\w-]+)\s+' # 서비스 이름 (icmp, icmpv6 등)
    r'[\d\.a-fA-F:]+/\d+->[\d\.a-fA-F:]+/\d+\s+' # 중간 부분 (고정 패턴)
    r'.*?A\s+(\d+)\s+([\w-]+)\s+([\w-]+)\s+([\w-]+)' # 프로토콜 ID, 정책 이름, 소스 존, 대상 존
)

# 장비명 추출을 위한 정규식
DEVICE_NAME_PATTERN = re.compile(r'^.*?(\w+(?:-\w+)*)\s+RT_FLOW:')

# 타임스탬프 추출을 위한 정규식
TIMESTAMP_PATTERN = re.compile(r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)')

# 프로토콜 번호 매핑
PROTOCOL_MAP = {
    1: 'icmp',
    6: 'tcp',
    17: 'udp',
    58: 'icmpv6',
    # 필요에 따라 추가
}

class LogParser:
    """주니퍼 방화벽 로그를 파싱하는 클래스"""
    
    def __init__(self, log_file=None, log_dir=None, log_files=None):
        """
        초기화
        
        Args:
            log_file (str): 분석할 단일 로그 파일 경로
            log_dir (str): 분석할 여러 로그 파일이 있는 디렉토리 경로
            log_files (list): 분석할 로그 파일 목록
        """
        self.log_file = log_file
        self.log_dir = log_dir
        self.log_files = log_files
        self.logs = []
        self.df = None

    def parse_log_line(self, line):
        """
        단일 로그 라인을 파싱 (IPv4/IPv6 지원)
        
        Args:
            line (str): 로그 라인
            
        Returns:
            dict: 파싱된 로그 정보 또는 None (파싱 실패 시)
        """
        match = JUNIPER_SESSION_PATTERN.match(line)
        if not match:
            return None
        
        try:
            close_reason, src_ip, src_port, dst_ip, dst_port, service_name, protocol_id, policy_name, src_zone, dst_zone = match.groups()
            
            # IPv4/IPv6 주소 유효성 확인
            try:
                # IPv6 주소인지 확인 (콜론을 포함하는 경우)
                if ':' in src_ip:
                    ipaddress.IPv6Address(src_ip)
                    is_ipv6 = True
                else:
                    ipaddress.IPv4Address(src_ip)
                    is_ipv6 = False
                    
                # 목적지 주소도 동일한 타입이어야 함
                if ':' in dst_ip:
                    ipaddress.IPv6Address(dst_ip)
                    if not is_ipv6:
                        logger.warning(f"로그에서 IP 버전이 혼합됨: src={src_ip}, dst={dst_ip}")
                else:
                    ipaddress.IPv4Address(dst_ip)
                    if is_ipv6:
                        logger.warning(f"로그에서 IP 버전이 혼합됨: src={src_ip}, dst={dst_ip}")
            except ValueError as e:
                logger.warning(f"잘못된 IP 주소: {e}")
                return None

            # 문자열을 안전하게 정수로 변환하는 헬퍼 함수
            def safe_int(value, default=0):
                try:
                    return int(value)
                except (ValueError, TypeError):
                    return default

            # 포트를 정수로 변환
            src_port = safe_int(src_port)
            dst_port = safe_int(dst_port)
            
            # 세션 타입 확인 (CREATE 또는 CLOSE)
            session_type = "CREATE" if "SESSION_CREATE" in line else "CLOSE"
            
            # 프로토콜 ID 변환
            protocol_id = safe_int(protocol_id)
            protocol = PROTOCOL_MAP.get(protocol_id, 'unknown')

            # 타임스탬프 추출
            timestamp_match = TIMESTAMP_PATTERN.match(line)
            if timestamp_match:
                timestamp_str = timestamp_match.group(1)
                try:
                    # 연도가 없으므로 현재 연도 추가
                    current_year = datetime.now().year
                    timestamp = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
                except ValueError:
                    timestamp = datetime.now()
            else:
                timestamp = datetime.now()
            
            # 장비명 추출
            device_name = "unknown"
            device_match = DEVICE_NAME_PATTERN.match(line)
            if device_match:
                device_name = device_match.group(1)
            
            # 파싱된 데이터 반환
            return {
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'source_port': src_port,
                'destination_port': dst_port,
                'protocol_id': protocol_id,
                'protocol': protocol,
                'source_zone': src_zone,
                'destination_zone': dst_zone,
                'service_name': service_name if service_name else 'unknown',
                'policy_name': policy_name,
                'session_type': session_type,
                'close_reason': close_reason,
                'timestamp': timestamp,
                'is_ipv6': is_ipv6,
                'device_name': device_name
            }
        except Exception as e:
            # 예외 발생 시 로그 출력 및 None 반환
            logger.error(f"로그 라인 파싱 오류: {e}")
            return None
    
    def process_log_file(self, file_path):
        """
        로그 파일 처리
        
        Args:
            file_path (str): 로그 파일 경로
            
        Returns:
            list: 파싱된 로그 엔트리 목록
        """
        logger.info(f"로그 파일 처리 중: {file_path}")
        entries = []
        
        try:
            with open(file_path, 'r', errors='ignore') as f:
                for line in f:
                    entry = self.parse_log_line(line)
                    if entry:
                        entries.append(entry)
        except Exception as e:
            logger.error(f"파일 {file_path} 처리 오류: {e}")
        
        logger.info(f"{file_path}에서 {len(entries)}개의 유효한 로그 항목 추출")
        return entries
    
    def process_logs(self):
        """
        지정된 파일 또는 디렉토리의 모든 로그 처리
        
        Returns:
            DataFrame: 파싱된 로그 데이터를 포함하는 DataFrame
        """
        all_entries = []
        
        if self.log_file:
            all_entries.extend(self.process_log_file(self.log_file))
        
        elif self.log_dir:
            log_files = [os.path.join(self.log_dir, f) for f in os.listdir(self.log_dir) 
                        if os.path.isfile(os.path.join(self.log_dir, f))]
            
            for log_file in log_files:
                all_entries.extend(self.process_log_file(log_file))
        
        elif self.log_files:
            for log_file in self.log_files:
                all_entries.extend(self.process_log_file(log_file))
        
        self.logs = all_entries
        
        if all_entries:
            self.df = pd.DataFrame(all_entries)
            
            # 중복 제거 및 정리
            self.df.drop_duplicates(inplace=True)
            logger.info(f"총 고유 로그 항목: {len(self.df)}")
        else:
            self.df = pd.DataFrame()
            logger.warning("유효한 로그 항목을 찾을 수 없습니다!")
        
        return self.df 

