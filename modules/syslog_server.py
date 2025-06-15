#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
방화벽 정책 추천 시스템 - Syslog 서버
----------------------------------
방화벽에서 전송되는 Syslog 메시지를 수신하고 저장합니다.
"""

import os
import re
import socket
import logging
import threading
import time
import json
import numpy as np
from datetime import datetime, timedelta

from modules.log_parser import LogParser
from modules.traffic_analyzer import TrafficAnalyzer

logger = logging.getLogger(__name__)

class SyslogServer:
    """Syslog 메시지를 수신하고 저장하는 서버"""
    
    def __init__(self, host='0.0.0.0', port=514, log_dir='./logs',
                 analysis_interval=3600, output_dir='./output',
                 device_filter='', device_filter_type='all',
                 regex_filter='', regex_filter_type='include',
                 retention_days=7, max_file_size_mb=200):
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
            regex_filter (str): 정규식 필터
            regex_filter_type (str): 정규식 필터 타입 ('include' 또는 'exclude')
            retention_days (int): 로그 파일 보관 기간 (일)
            max_file_size_mb (int): 로그 파일 최대 크기 (MB)
        """
        self.host = host
        self.port = port
        self.log_dir = log_dir
        self.output_dir = output_dir
        self.analysis_interval = analysis_interval
        self.device_filter = device_filter.strip()
        self.device_filter_type = device_filter_type
        self.regex_filter = regex_filter.strip()
        self.regex_filter_type = regex_filter_type
        self.retention_days = retention_days
        self.max_file_size_mb = max_file_size_mb
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024  # MB -> 바이트
        # 분석된 로그 파일 목록을 저장할 속성 추가
        self.analyzed_logs_file = os.path.join(output_dir, 'analyzed_logs.json')
        self.analyzed_logs = self._load_analyzed_logs()
    
        # 정규식 패턴 컴파일 (성능 향상을 위해)
        self.regex_pattern = None
        if self.regex_filter:
            try:
                self.regex_pattern = re.compile(self.regex_filter)
            except re.error as e:
                logger.error(f"정규식 컴파일 오류: {e}")
                self.regex_pattern = None
    
        # Syslog용 UDP 소켓
        self.sock = None
    
        # 로그 파일 핸들
        self.log_files = {}
    
        # 현재 로그 파일 크기 트래킹
        self.log_file_sizes = {}
    
        # 서버 상태
        self.running = False
    
        # 마지막 자동 분석 시간
        self.last_analysis_time = datetime.now()
    
        # 마지막 로그 정리 시간
        self.last_cleanup_time = datetime.now()
    
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

        # 정규식 필터 적용 (추가)
        if self.regex_pattern:
            match = self.regex_pattern.search(message)
        
            if self.regex_filter_type == 'include':
                # 포함 필터: 정규식에 매치되는 것만 허용
                if not match:
                    return
            elif self.regex_filter_type == 'exclude':
                # 제외 필터: 정규식에 매치되는 것은 제외
                if match:
                    return
        
        # 날짜와 시간 분리하여 생성 - 수정된 부분
        current_time = datetime.now()
        date_str = current_time.strftime('%Y%m%d')
        time_str = current_time.strftime('%H%M%S')
        
        # 장비명이 있으면 장비명_날짜_시간.log, 없으면 All_날짜_시간.log로 저장
        device_name = "All"
        
        device_match = re.search(r'^.*?(\w+(?:-\w+)*)\s+RT_FLOW:', message)
        if device_match:
            device_name = device_match.group(1)

        # 장비별 현재 로그 파일 확인
        current_log_file = None
        for file_path, file_handle in self.log_files.items():
            if file_path.startswith(os.path.join(self.log_dir, f"{device_name}_")):
                current_log_file = file_path
                break

        # 현재 로그 파일이 없거나 최대 크기를 초과한 경우 새 파일 생성
        if current_log_file is None or (current_log_file in self.log_file_sizes and
                                       self.log_file_sizes[current_log_file] >= self.max_file_size_bytes):
            if current_log_file is not None:
                # 기존 파일 핸들 닫기
                try:
                    self.log_files[current_log_file].close()
                    del self.log_files[current_log_file]
                    del self.log_file_sizes[current_log_file]
                    logger.info(f"최대 크기 도달로 로그 파일 닫힘: {current_log_file}")
                except Exception as e:
                    logger.error(f"파일 핸들 닫기 오류 {current_log_file}: {e}")

            # 새 로그 파일 생성 - 수정된 이름 형식
            log_file_name = f"{device_name}_{date_str}_{time_str}.log"
            log_file_path = os.path.join(self.log_dir, log_file_name)

            try:
                file_handle = open(log_file_path, 'a', encoding='utf-8')
                self.log_files[log_file_path] = file_handle
                self.log_file_sizes[log_file_path] = 0
                logger.info(f"새 로그 파일 생성됨: {log_file_path}")
            except Exception as e:
                logger.error(f"로그 파일 생성 오류 {log_file_path}: {e}")
                return

            current_log_file = log_file_path

        # 메시지 로그 파일에 기록
        try:
            message_bytes = (message + '\n').encode('utf-8')
            message_size = len(message_bytes)

            self.log_files[current_log_file].write(message + '\n')
            self.log_files[current_log_file].flush()

            # 파일 크기 업데이트
            self.log_file_sizes[current_log_file] += message_size
        except Exception as e:
            logger.error(f"로그 파일 쓰기 오류 {current_log_file}: {e}")
    
    def run_analysis_thread(self):
        """자동 분석 스레드 실행"""
        while self.running:
            # 분석 주기 확인
            now = datetime.now()
            time_since_last_analysis = now - self.last_analysis_time
        
            if time_since_last_analysis.total_seconds() >= self.analysis_interval:
                # 분석 수행
                self.perform_automatic_analysis()
                self.last_analysis_time = now
        
            # 매 시간마다 로그 정리 수행
            time_since_last_cleanup = now - self.last_cleanup_time
            if time_since_last_cleanup.total_seconds() >= 3600:  # 1시간
                self.cleanup_old_logs()
                self.last_cleanup_time = now
        
            # 잠시 대기 (10초 간격으로 체크)
            time.sleep(10)

    def sanitize_for_json(self, obj):
        """
        JSON 직렬화를 위해 numpy 타입 등을 파이썬 기본 타입으로 변환
        
        Args:
            obj: 변환할 객체
            
        Returns:
            변환된 객체
        """
        if isinstance(obj, dict):
            return {k: self.sanitize_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self.sanitize_for_json(v) for v in obj]
        elif isinstance(obj, np.bool_):
            return bool(obj)
        elif isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        else:
            return obj

    def perform_automatic_analysis(self):
        """자동 로그 분석 수행"""
        logger.info("자동 로그 분석 시작...")
    
        try:
            # 오래된 로그 파일 핸들 닫기 - 수정된 파일명 파싱 적용
            for file_path, file_handle in list(self.log_files.items()):
                # 파일이 1시간 이상 지났으면 핸들 닫기 (분석을 위해)
                file_name = os.path.basename(file_path)
                # 파일명 "장비명_YYYYMMDD_HHMMSS.log" 형식 파싱
                parts = file_name.rsplit('_', 2)
                if len(parts) == 3:  # [장비명, 날짜, 시간.log] 형태
                    date_str = parts[1]
                    time_str = parts[2].split('.')[0]  # .log 제거
                    if len(date_str) == 8 and date_str.isdigit():
                        try:
                            file_time = datetime.strptime(f"{date_str}_{time_str}", '%Y%m%d_%H%M%S')
                            if (datetime.now() - file_time).total_seconds() > 3600:  # 1시간
                                try:
                                    file_handle.close()
                                    del self.log_files[file_path]
                                    if file_path in self.log_file_sizes:
                                        del self.log_file_sizes[file_path]
                                    logger.info(f"오래된 로그 파일 핸들 닫힘: {file_path}")
                                except Exception as e:
                                    logger.error(f"파일 핸들 닫기 오류 {file_path}: {e}")
                        except (ValueError, IndexError):
                            logger.warning(f"파일명 파싱 오류: {file_name}")
            
            # 로그 파일 정리 (보관 기간 적용)
            self.cleanup_old_logs()
    
            # 로그 파일 목록 가져오기 - 이전에 분석되지 않은 파일만 필터링
            log_files = []
            for filename in os.listdir(self.log_dir):
                if filename.endswith('.log'):
                    log_path = os.path.join(self.log_dir, filename)
                    # 이전 분석에서 이미 사용한 로그 파일은 제외
                    if log_path not in self.analyzed_logs:
                        log_files.append(log_path)
    
            if not log_files:
                logger.info("분석할 새로운 로그 파일이 없습니다.")
                return
    
            logger.info(f"{len(log_files)}개의 새로운 로그 파일 분석 중...")
    
            # 각 로그 파일별로 개별 분석
            for log_file in log_files:
                self.analyze_single_log_file(log_file)
                # 분석된 로그 파일 목록에 추가
                self.analyzed_logs.append(log_file)
            
            # 분석된 로그 파일 목록 저장
            self._save_analyzed_logs()
            
            # 현재 열려 있는 로그 파일 모두 닫고 새 로그 파일 생성
            self._rotate_log_files()
    
        except Exception as e:
            logger.error(f"자동 분석 오류: {e}")
    
    def analyze_single_log_file(self, log_file):
        """
        개별 로그 파일 분석 (자동 분석)
        
        Args:
            log_file (str): 분석할 로그 파일 경로
        """
        logger.info(f"로그 파일 분석 시작: {log_file}")
    
        try:
            # 로그 파싱
            parser = LogParser(log_files=[log_file])
            log_df = parser.process_logs()
    
            if log_df.empty:
                logger.warning(f"파싱된 로그 데이터가 없습니다: {log_file}")
                return
    
            # 파일명에서 타임스탬프 추출 - 수정된 방식
            file_basename = os.path.basename(log_file)  # 예: "P_FW_1_20250517_123045.log"
            
            # .log 확장자 제거
            file_name_without_ext = file_basename.rsplit('.', 1)[0]  # 예: "P_FW_1_20250517_123045"
            
            # 맨 오른쪽에서 2번째 '_'를 기준으로 분리
            parts = file_name_without_ext.rsplit('_', 2)  # ['P_FW_1', '20250517', '123045']
            
            if len(parts) == 3:  # [장비명, 날짜, 시간] 형태로 분리됨
                date_part = parts[1]    # YYYYMMDD
                time_part = parts[2]    # HHMMSS
                
                # 타임스탬프 생성
                timestamp = f"{date_part}_{time_part}"  # YYYYMMDD_HHMMSS 형식
            else:
                # 형식이 예상과 다른 경우 현재 시간 사용
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
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
    
            # 주니퍼 설정 생성
            from modules.policy_generator import PolicyGenerator
            config = PolicyGenerator(policies).generate_juniper_config()
    
            # 시각화 생성
            sankey_prefix = os.path.join(self.output_dir, f"traffic_sankey_{timestamp}")
            viz3d_prefix = os.path.join(self.output_dir, f"traffic_3d_interactive_{timestamp}")
    
            # Sankey 다이어그램
            sankey_files = analyzer.visualize_traffic_sankey(sankey_prefix)
    
            # 3D 인터랙티브 시각화
            viz_files = analyzer.visualize_traffic_patterns_3d_interactive(viz3d_prefix)
    
            # 장비명 정보 수집 - 로그 내용에서만 추출
            device_names = []
            if 'device_name' in log_df.columns:
                log_device_names = list(log_df['device_name'].unique())
                # 'unknown'이 아닌 유효한 장비명만 필터링
                device_names = [name for name in log_device_names if name and name.strip() != 'unknown']
            
            # 장비명이 없는 경우 기본값 설정
            if not device_names:
                device_names = ['Unknown_Device']
                logger.warning(f"로그에서 유효한 장비명을 찾을 수 없습니다. 파일: {log_file}")
    
            logger.info(f"자동 분석 - 로그에서 추출된 장비명: {device_names}")
    
            # 로그 파일명만 추출 (경로 제외)
            log_filenames = [os.path.basename(log_file)]
    
            # 분석 결과 저장
            result = {
                'timestamp': timestamp,
                'params': params,
                'policies': policies,
                'config': config,
                'top_traffic': top_traffic_df.to_dict('records') if top_traffic_df is not None else [],
                'visualizations': {
                    'sankey': sankey_files,
                    'interactive_3d': viz_files
                },
                'source': 'syslog',
                'log_files': [log_file],
                'log_filenames': log_filenames,
                'device_names': device_names,  # 로그에서만 추출된 장비명
                'filters_applied': False,
                'total_log_records': len(log_df),
                'filtered_log_records': len(log_df),
                'analysis_type': 'auto',  # 자동 분석임을 표시
                'syslog_filters': {
                    'device_filter': self.device_filter,
                    'device_filter_type': self.device_filter_type,
                    'regex_filter': self.regex_filter,
                    'regex_filter_type': self.regex_filter_type
                }
            }
    
            # 결과 파일 저장 - 장비명 사용
            if device_names and device_names[0] != 'Unknown_Device':
                device_name = device_names[0]
            else:
                device_name = "Unknown"
                
            result_file = os.path.join(self.output_dir, f"analysis_{device_name}_{timestamp}.json")
            
            # 데이터 정리 과정 추가 (NumPy 객체 처리)
            sanitized_result = self.sanitize_for_json(result)
    
            with open(result_file, 'w') as f:
                json.dump(sanitized_result, f, indent=2)
    
            logger.info(f"로그 파일 분석 완료: {log_file}, 결과 저장됨: {result_file}")
    
        except Exception as e:
            logger.error(f"로그 파일 분석 오류 {log_file}: {e}")

    def cleanup_old_logs(self):
        """
        보관 기간이 지난 로그 파일 삭제
        """
        logger.info(f"오래된 로그 파일 정리 (보관 기간: {self.retention_days}일)")
    
        try:
            now = datetime.now()
            cutoff_time = now - timedelta(days=self.retention_days)
            deleted_count = 0
            deleted_files = []  # 삭제된 파일 목록 추적
    
            for filename in os.listdir(self.log_dir):
                if not filename.endswith('.log'):
                    continue
    
                file_path = os.path.join(self.log_dir, filename)
    
                try:
                    # 파일명에서 타임스탬프 추출 - 수정
                    parts = filename.rsplit('_', 2)  # 예: ['장비명', '20250517', '123045.log']
                    
                    if len(parts) == 3:
                        date_str = parts[1]  # YYYYMMDD
                        time_str = parts[2].split('.')[0]  # HHMMSS (.log 제거)
                        
                        if len(date_str) == 8 and date_str.isdigit():
                            try:
                                file_time = datetime.strptime(f"{date_str}_{time_str}", '%Y%m%d_%H%M%S')
                            except ValueError:
                                # 파싱 실패 시 파일 수정 시간 사용
                                file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                        else:
                            file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                    else:
                        # 파일명 형식이 예상과 다를 경우 수정 시간 사용
                        file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
    
                    # 보관 기간보다 오래된 파일 삭제
                    if file_time < cutoff_time:
                        # 파일이 현재 열려있는지 확인
                        if file_path in self.log_files:
                            try:
                                self.log_files[file_path].close()
                                del self.log_files[file_path]
                                if file_path in self.log_file_sizes:
                                    del self.log_file_sizes[file_path]
                            except Exception as e:
                                logger.error(f"파일 핸들 닫기 오류 {file_path}: {e}")
    
                        # 파일 삭제
                        os.remove(file_path)
                        deleted_count += 1
                        deleted_files.append(file_path)  # 삭제된 파일 목록에 추가
                        logger.info(f"오래된 로그 파일 삭제됨: {file_path}")

                except Exception as e:
                    logger.error(f"로그 파일 정리 중 오류 {file_path}: {e}")
    
            logger.info(f"로그 파일 정리 완료: {deleted_count}개 파일 삭제됨")
            # 분석된 로그 파일 목록에서 삭제된 파일 제거
            if hasattr(self, 'analyzed_logs') and deleted_files:
                self.analyzed_logs = [log for log in self.analyzed_logs if log not in deleted_files]
                self._save_analyzed_logs()
    
        except Exception as e:
            logger.error(f"로그 파일 정리 오류: {e}")

    def _load_analyzed_logs(self):
        """
        분석된 로그 파일 목록을 로드
        """
        if os.path.exists(self.analyzed_logs_file):
            try:
                with open(self.analyzed_logs_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"분석된 로그 파일 목록 로드 오류: {e}")
        return []
    
    def _save_analyzed_logs(self):
        """
        분석된 로그 파일 목록을 저장
        """
        try:
            with open(self.analyzed_logs_file, 'w') as f:
                json.dump(self.analyzed_logs, f)
        except Exception as e:
            logger.error(f"분석된 로그 파일 목록 저장 오류: {e}")

    def _rotate_log_files(self):
        """
        현재 열려 있는 로그 파일을 모두 닫고 새 로그 파일 생성 준비
        """
        logger.info("로그 파일 순환 중...")
        
        # 현재 열려 있는 모든 로그 파일 핸들 닫기
        for file_path, file_handle in list(self.log_files.items()):
            try:
                file_handle.close()
                del self.log_files[file_path]
                if file_path in self.log_file_sizes:
                    del self.log_file_sizes[file_path]
                logger.info(f"로그 파일 닫힘: {file_path}")
            except Exception as e:
                logger.error(f"파일 핸들 닫기 오류 {file_path}: {e}")
        
        # 새 로그 파일은 다음 메시지가 도착할 때 자동으로 생성됨
        logger.info("로그 파일 순환 완료. 새 로그 파일은 다음 메시지 수신 시 생성됩니다.")
