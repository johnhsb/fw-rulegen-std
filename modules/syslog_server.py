#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
방화벽 정책 추천 시스템 - Syslog 서버
----------------------------------
방화벽에서 전송되는 Syslog 메시지를 수신하고 저장합니다.
"""

import os
import socket
import logging
import threading
import time
import json
from datetime import datetime, timedelta

from modules.log_parser import LogParser
from modules.traffic_analyzer import TrafficAnalyzer

logger = logging.getLogger(__name__)

class SyslogServer:
    """Syslog 메시지를 수신하고 저장하는 서버"""
    
    def __init__(self, host='0.0.0.0', port=514, log_dir='./logs', 
                 analysis_interval=3600, output_dir='./output',
                 device_filter='', device_filter_type='all'):
        """
        초기화
        
        Args:
            host (str): 바인딩할 호스트 주소
            port (int): 바인딩할 포트 번호
            log_dir (str): 로그 저장 디렉토리
            analysis_interval (int): 자동 분석 주기 (초)
            output_dir (str): 분석 결과 저장 디렉토리
            device_filter (str): 장비명 필터
            device_filter_type (str): 필터 타입 ('include' 또는 'exclude')
        """
        self.host = host
        self.port = port
        self.log_dir = log_dir
        self.output_dir = output_dir
        self.analysis_interval = analysis_interval
        self.device_filter = device_filter.strip()
        self.device_filter_type = device_filter_type
        
        # Syslog용 UDP 소켓
        self.sock = None
        
        # 로그 파일 핸들
        self.log_files = {}
        
        # 서버 상태
        self.running = False
        
        # 마지막 자동 분석 시간
        self.last_analysis_time = datetime.now()
        
        # 자동 분석 스레드
        self.analysis_thread = None
    
    def start(self):
        """Syslog 서버 시작"""
        if self.running:
            logger.warning("Syslog 서버가 이미 실행 중입니다.")
            return
        
        try:
            # 로그 디렉토리 생성
            os.makedirs(self.log_dir, exist_ok=True)
            os.makedirs(self.output_dir, exist_ok=True)
            
            # UDP 소켓 생성 및 바인딩
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((self.host, self.port))
            
            self.running = True
            
            logger.info(f"Syslog 서버가 {self.host}:{self.port}에서 시작되었습니다.")
            
            # 분석 스레드 시작
            if self.analysis_interval > 0:
                self.analysis_thread = threading.Thread(target=self.run_analysis_thread)
                self.analysis_thread.daemon = True
                self.analysis_thread.start()
                logger.info(f"자동 분석 스레드가 시작되었습니다 (주기: {self.analysis_interval}초)")
            
            # 메시지 수신 루프
            self.receive_messages()
            
        except Exception as e:
            logger.error(f"Syslog 서버 시작 오류: {e}")
            self.running = False
            
            if self.sock:
                self.sock.close()
                self.sock = None
    
    def stop(self):
        """Syslog 서버 중지"""
        self.running = False
        
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
        
        # 열린 모든 로그 파일 닫기
        for file_handle in self.log_files.values():
            try:
                file_handle.close()
            except:
                pass
        
        self.log_files = {}
        
        logger.info("Syslog 서버가 중지되었습니다.")
    
    def receive_messages(self):
        """Syslog 메시지 수신 및 처리"""
        buffer_size = 8192  # 8KB 버퍼
        
        while self.running:
            try:
                # 메시지 수신
                data, addr = self.sock.recvfrom(buffer_size)
                message = data.decode('utf-8', errors='ignore')
                
                # 메시지 처리
                self.process_message(message, addr)
                
            except socket.timeout:
                # 타임아웃은 무시
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"메시지 수신 오류: {e}")
                    time.sleep(1)  # 오류 발생 시 잠시 대기
    
    def process_message(self, message, addr):
        """
        Syslog 메시지 처리
        
        Args:
            message (str): 수신된 Syslog 메시지
            addr (tuple): 송신자 주소
        """
        # 필터 적용 (필터가 설정된 경우)
        if self.device_filter:
            # 장비명 확인
            import re
            device_match = re.search(r'^.*?(\w+(?:-\w+)*)\s+RT_FLOW:', message)
            
            if device_match:
                device_name = device_match.group(1)
                
                # 필터 타입에 따라 처리
                if self.device_filter_type == 'include':
                    # 포함 필터: 지정된 장비만 허용
                    if self.device_filter != device_name:
                        return
                elif self.device_filter_type == 'exclude':
                    # 제외 필터: 지정된 장비는 제외
                    if self.device_filter == device_name:
                        return
            elif self.device_filter_type == 'include':
                # 장비명이 없고 포함 필터인 경우 무시
                return
        
        # 날짜 확인
        today = datetime.now().strftime('%Y%m%d')
        
        # 필터에 맞는 메시지를 로그 파일에 기록
        # 장비명이 있으면 장비명_날짜.log, 없으면 All_날짜.log로 저장
        device_name = "All"
        
        import re
        device_match = re.search(r'^.*?(\w+(?:-\w+)*)\s+RT_FLOW:', message)
        if device_match:
            device_name = device_match.group(1)
        
        log_file_name = f"{device_name}_{today}.log"
        log_file_path = os.path.join(self.log_dir, log_file_name)
        
        # 로그 파일 핸들 가져오기 또는 생성
        if log_file_path not in self.log_files:
            try:
                file_handle = open(log_file_path, 'a', encoding='utf-8')
                self.log_files[log_file_path] = file_handle
                logger.info(f"로그 파일 생성됨: {log_file_path}")
            except Exception as e:
                logger.error(f"로그 파일 생성 오류 {log_file_path}: {e}")
                return
        
        # 메시지 로그 파일에 기록
        try:
            self.log_files[log_file_path].write(message + '\n')
            self.log_files[log_file_path].flush()
        except Exception as e:
            logger.error(f"로그 파일 쓰기 오류 {log_file_path}: {e}")
    
    def run_analysis_thread(self):
        """자동 분석 스레드 실행"""
        while self.running:
            # 분석 주기 확인
            now = datetime.now()
            time_since_last = now - self.last_analysis_time
            
            if time_since_last.total_seconds() >= self.analysis_interval:
                # 분석 수행
                self.perform_automatic_analysis()
                self.last_analysis_time = now
            
            # 잠시 대기 (10초 간격으로 체크)
            time.sleep(10)
    
    def perform_automatic_analysis(self):
        """자동 로그 분석 수행"""
        logger.info("자동 로그 분석 시작...")
        
        try:
            # 오래된 로그 파일 핸들 닫기
            today = datetime.now().strftime('%Y%m%d')
            
            for file_path, file_handle in list(self.log_files.items()):
                if today not in os.path.basename(file_path):
                    try:
                        file_handle.close()
                        del self.log_files[file_path]
                        logger.info(f"오래된 로그 파일 핸들 닫힘: {file_path}")
                    except Exception as e:
                        logger.error(f"파일 핸들 닫기 오류 {file_path}: {e}")
            
            # 로그 파일 목록 가져오기
            log_files = []
            for filename in os.listdir(self.log_dir):
                if filename.endswith('.log'):
                    log_files.append(os.path.join(self.log_dir, filename))
            
            if not log_files:
                logger.info("분석할 로그 파일이 없습니다.")
                return
            
            # 로그 파싱
            parser = LogParser(log_files=log_files)
            log_df = parser.process_logs()
            
            if log_df.empty:
                logger.warning("파싱된 로그 데이터가 없습니다.")
                return
            
            # 클러스터링 파라미터 설정
            params = {
                'min_occurrences': 1,
                'eps': 0.5,
                'min_samples': 2,
                'max_data_points': 10000
            }
            
            # 트래픽 분석
            analyzer = TrafficAnalyzer(log_df, **params)
            analyzer.cluster_traffic_patterns()
            
            # 상위 트래픽 패턴 분석
            top_traffic_df = analyzer.analyze_top_traffic_patterns(top_n=30)
            
            # 정책 추천 생성
            policies = analyzer.generate_policy_recommendations()
            
            # 시각화 생성
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_prefix = os.path.join(self.output_dir, f"auto_analysis_{timestamp}")
            
            # Sankey 다이어그램
            sankey_files = analyzer.visualize_traffic_sankey(output_prefix + "_sankey")
            
            # 3D 인터랙티브 시각화
            viz_files = analyzer.visualize_traffic_patterns_3d_interactive(output_prefix + "_3d")
            
            # 분석 결과 저장
            result = {
                'timestamp': timestamp,
                'params': params,
                'policies': policies,
                'top_traffic': top_traffic_df.to_dict('records') if top_traffic_df is not None else [],
                'visualizations': {
                    'sankey': sankey_files,
                    'interactive_3d': viz_files
                },
                'source': 'syslog',
                'log_files': log_files
            }
            
            # 결과 파일 저장
            result_file = os.path.join(self.output_dir, f"analysis_{timestamp}.json")
            with open(result_file, 'w') as f:
                json.dump(result, f, indent=2)
            
            logger.info(f"자동 분석 완료. 결과 저장됨: {result_file}")
            
        except Exception as e:
            logger.error(f"자동 분석 오류: {e}")

