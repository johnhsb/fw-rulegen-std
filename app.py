#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ML기반 방화벽 정책 추천 시스템 - 메인 애플리케이션
--------------------------------------------------
방화벽 로그 분석 및 정책 추천 웹 애플리케이션
"""

import os
import sys
import logging
import json
import hashlib
import ipaddress
import pandas as pd
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_file, make_response, abort
from flask_session import Session
from gevent.pywsgi import WSGIServer
import ssl

# 모듈 임포트
from modules.auth import load_user_config, hash_password, login_required
from modules.log_parser import LogParser
from modules.traffic_analyzer import TrafficAnalyzer
from modules.policy_generator import PolicyGenerator
from modules.syslog_server import SyslogServer
from config.config import Config, load_system_settings, save_system_settings

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("firewall_recommender.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("firewall-policy-recommender")

# Flask 앱 초기화
app = Flask(__name__)
app.config.from_object(Config)
Session(app)

# 전역 상태 관리
global_state = {
    'analyzer': None,        # 트래픽 분석기 인스턴스
    'log_df': None,          # 로그 데이터프레임
    'policies': [],          # 생성된 정책
    'config': [],            # 생성된 주니퍼 설정
    'syslog_server': None,   # Syslog 서버 인스턴스
    'is_syslog_running': False,  # Syslog 서버 실행 상태
    'syslog_config': {       # Syslog 서버 설정
        'host': '0.0.0.0',
        'port': 514,
        'interval': 3600,
        'device_filter': '',
        'device_filter_type': 'all',
        'regex_filter': '',
        'regex_filter_type': 'include'
    },
    'dbscan_params': {       # DBSCAN 파라미터 설정
        'min_occurrences': 1,
        'eps': 0.5,
        'min_samples': 2,
        'max_data_points': 10000
    }
}

# 필요한 디렉토리 생성
for directory in [Config.UPLOAD_DIR, Config.OUTPUT_DIR, Config.LOGS_DIR]:
    os.makedirs(directory, exist_ok=True)

# 저장된 설정 로드
saved_settings = load_system_settings()

# DBSCAN 파라미터 적용
if 'dbscan_params' in saved_settings:
    global_state['dbscan_params'].update(saved_settings['dbscan_params'])

# Syslog 설정 적용
if 'syslog_config' in saved_settings:
    global_state['syslog_config'].update(saved_settings['syslog_config'])
    
# 출력 디렉토리 설정 적용
if 'output_dir' in saved_settings:
    Config.OUTPUT_DIR = saved_settings['output_dir']

# 사용자 목록 로드
users = load_user_config(Config.USERS_CONFIG)

#----- 라우트 정의 -----#

@app.route('/')
@login_required
def index():
    """대시보드 메인 페이지"""
    # 분석 결과 목록 가져오기
    manual_analyses = get_analyses_list('upload')
    syslog_analyses = get_analyses_list('syslog')
    
    # 로그 파일 목록 가져오기
    manual_logs = get_logs_list('upload')
    syslog_logs = get_logs_list('syslog')
    
    return render_template('index.html',
                          is_analyzed=global_state['analyzer'] is not None,
                          is_syslog_running=global_state['is_syslog_running'],
                          manual_analyses=manual_analyses,
                          syslog_analyses=syslog_analyses,
                          manual_logs=manual_logs,
                          syslog_logs=syslog_logs)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """로그인 페이지"""
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # 사용자 확인
        if username in users and users[username] == hash_password(password):
            session['logged_in'] = True
            session['username'] = username
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            error = '잘못된 사용자 이름 또는 비밀번호입니다.'
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    """로그아웃 처리"""
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_logs():
    """로그 파일 업로드 처리"""
    if request.method == 'POST':
        if 'logfile' not in request.files:
            return jsonify({'error': '파일이 선택되지 않았습니다'}), 400
        
        uploaded_files = request.files.getlist('logfile')
        if not uploaded_files or uploaded_files[0].filename == '':
            return jsonify({'error': '파일이 선택되지 않았습니다'}), 400
        
        # 기존 업로드 제거
        for file in os.listdir(Config.UPLOAD_DIR):
            os.remove(os.path.join(Config.UPLOAD_DIR, file))
        
        # 새 파일 저장
        file_paths = []
        for file in uploaded_files:
            file_path = os.path.join(Config.UPLOAD_DIR, file.filename)
            file.save(file_path)
            file_paths.append(file_path)
        
        session['uploaded_files'] = file_paths
        return jsonify({'success': True, 'files': file_paths})
    
    return render_template('upload.html')

@app.route('/analyze', methods=['GET'])
@login_required
def analyze_logs():
    """로그 분석 실행"""
    # 타임스탬프로 특정 분석 결과 보기
    timestamp = request.args.get('timestamp')
    if timestamp:
        # 분석 결과 파일 존재 확인
        analysis_result = load_analysis_result(timestamp)
        if not analysis_result:
            logger.warning(f"요청된 타임스탬프에 대한 분석 결과 없음: {timestamp}")
            flash('요청한 분석 결과를 찾을 수 없습니다.', 'warning')
            return redirect(url_for('index'))
            
        # 분석 결과 파일 찾기 및 표시
        return render_template('analyze.html', 
                              timestamp=timestamp,
                              params=global_state['dbscan_params'])
        
    # 일반 분석 페이지
    return render_template('analyze.html', params=global_state['dbscan_params'])

@app.route('/api/analyze', methods=['POST'])
@login_required
def api_analyze_logs():
    """로그 분석 API 엔드포인트"""
    # 분석 파라미터 가져오기
    params = {
        'min_occurrences': int(request.form.get('min_occurrences', 1)),
        'eps': float(request.form.get('eps', 0.5)),
        'min_samples': int(request.form.get('min_samples', 2)),
        'max_data_points': int(request.form.get('max_data_points', 10000))
    }

    # 필터 파라미터 가져오기
    filters = get_filter_params_from_request(request.form)
    top_n = int(request.form.get('top_n', 50))
    
    # 타임스탬프 확인 - 기존 분석 결과 재분석 여부 확인
    previous_timestamp = request.form.get('timestamp')
    
    # 분석 타입 결정 로직
    analysis_type = 'manual'  # 기본값: 수동 분석
    source_type = 'upload'    # 기본값: 업로드
    original_analysis_type = None
    source_filename = None
    
    # 로그 파일 목록 초기화
    log_files = []
    
    if previous_timestamp:
        logger.info(f"기존 분석 결과({previous_timestamp})에 새 필터 적용 시도")
        # 기존 분석 결과에서 메타데이터 가져오기
        analysis_result = load_analysis_result(previous_timestamp)
        
        if analysis_result:
            # 원본 분석 타입 정보 가져오기
            original_analysis_type = analysis_result.get('analysis_type', 'auto')
            source_type = analysis_result.get('source', 'upload')
            source_filename = analysis_result.get('source_filename', '')
            log_files = analysis_result.get('log_files', [])
            
            # 재분석 타입 결정
            if original_analysis_type == 'single_file':
                analysis_type = 'single_file_reanalysis'  # 개별파일 재분석
            elif original_analysis_type == 'auto':
                analysis_type = 'auto_reanalysis'  # 자동분석 재분석
            else:
                analysis_type = 'manual_reanalysis'  # 수동분석 재분석
            
            # 모든 로그 파일이 존재하는지 확인
            all_files_exist = all(os.path.exists(file_path) for file_path in log_files)
            
            if not all_files_exist:
                missing_files = [file_path for file_path in log_files if not os.path.exists(file_path)]
                logger.warning(f"일부 원본 로그 파일을 찾을 수 없습니다: {missing_files}")
                
                if source_type == 'upload':
                    return jsonify({'error': '원본 로그 파일을 찾을 수 없습니다. 파일을 다시 업로드해주세요.'}), 400
                else:  # syslog
                    return jsonify({'error': '원본 Syslog 파일을 찾을 수 없습니다. 새로운 로그가 수집되기를 기다리거나 다른 분석 결과를 선택하세요.'}), 400
            
            logger.info(f"기존 분석 결과에서 {len(log_files)}개의 로그 파일 경로 로드 (원본 타입: {original_analysis_type})")
    
    # 타임스탬프가 없거나 해당 타임스탬프의 로그 파일이 없는 경우
    if not log_files:
        # 기존 로직: 업로드된 파일 확인
        uploaded_files = session.get('uploaded_files', [])
        
        if not uploaded_files:
            return jsonify({'error': '로그 파일을 먼저 업로드해 주세요'}), 400
            
        log_files = uploaded_files
        analysis_type = 'manual'  # 새로운 수동 분석
        source_type = 'upload'
        logger.info(f"세션에서 {len(log_files)}개의 업로드된 로그 파일 경로 로드")

    try:
        # 로그 파싱
        parser = LogParser(log_files=log_files)
        log_df = parser.process_logs()

        if log_df.empty:
            return jsonify({'error': '유효한 로그 데이터를 찾을 수 없습니다'}), 400

        # 필터링 적용
        filtered_df = apply_filters(log_df, filters)

        if filtered_df.empty:
            return jsonify({'error': '필터링 후 남은 로그 데이터가 없습니다. 필터 조건을 완화해 주세요.'}), 400

        # 트래픽 분석
        analyzer = TrafficAnalyzer(filtered_df, **params)
        analyzer.cluster_traffic_patterns()

        # 분석 결과 생성
        top_traffic_df = analyzer.analyze_top_traffic_patterns(top_n=top_n, subnet_grouping='/32')
        policies = analyzer.generate_policy_recommendations()
        config = PolicyGenerator(policies).generate_juniper_config()

        # 시각화 생성
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        visualizations = create_visualizations(analyzer, timestamp)

        # 장비명 정보 수집 - 로그 내용에서만 추출
        device_names = []
        if 'device_name' in filtered_df.columns:
            log_device_names = list(filtered_df['device_name'].unique())
            # 'unknown'이 아닌 유효한 장비명만 필터링
            device_names = [name for name in log_device_names if name and name.strip() != 'unknown']

        # 장비명이 없는 경우 기본값 설정
        if not device_names:
            device_names = ['Unknown_Device']
            logger.warning(f"로그에서 유효한 장비명을 찾을 수 없습니다. 분석 타입: {analysis_type}")

        logger.info(f"일반 분석 - 로그에서 추출된 장비명: {device_names}")
        
        # 필터 적용 여부 확인
        filters_applied = any([
            filters.get('device_name_filter') and filters.get('device_name_filter').strip(),
            filters.get('source_ip_filter') and filters.get('source_ip_filter').strip(),
            filters.get('destination_ip_filter') and filters.get('destination_ip_filter').strip(),
            filters.get('port_filter') and filters.get('port_filter').strip(),
            filters.get('protocol_filter') and filters.get('protocol_filter').strip(),
            filters.get('source_zone_filter') and filters.get('source_zone_filter').strip(),
            filters.get('destination_zone_filter') and filters.get('destination_zone_filter').strip(),
            filters.get('exclude_noise')
        ])

        # 로그 파일명만 추출 (경로 제외)
        log_filenames = [os.path.basename(f) for f in log_files]

        # 분석 결과 저장 - analysis_type 포함
        save_analysis_results(timestamp, {
            'params': params,
            'filters': filters,
            'policies': policies,
            'config': config,
            'top_traffic': top_traffic_df.to_dict('records') if top_traffic_df is not None else [],
            'visualizations': visualizations,
            'source': source_type,
            'log_files': log_files,
            'log_filenames': log_filenames,
            'device_names': device_names,
            'filters_applied': filters_applied,
            'total_log_records': len(log_df),
            'filtered_log_records': len(filtered_df),
            'analysis_type': analysis_type,  # 올바른 분석 타입 설정
            'original_analysis_type': original_analysis_type,  # 원본 분석 타입 보존
            'source_filename': source_filename,  # 원본 파일명 보존 (개별파일 분석의 경우)
            'is_reanalysis': previous_timestamp is not None,  # 재분석 여부
            'previous_timestamp': previous_timestamp  # 원본 분석 타임스탬프
        })

        # 전역 상태 업데이트
        global_state['analyzer'] = analyzer
        global_state['log_df'] = filtered_df
        global_state['policies'] = policies
        global_state['config'] = config

        return jsonify({
            'success': True,
            'policies_count': len(policies),
            'timestamp': timestamp,
            'visualizations': visualizations,
            'analysis_type': analysis_type
        })

    except Exception as e:
        logger.error(f"API 분석 오류: {e}", exc_info=True)
        return jsonify({'error': f'분석 중 오류가 발생했습니다: {str(e)}'}), 500

@app.route('/api/analysis_data')
@login_required
def api_analysis_data():
    """타임스탬프로 분석 데이터 가져오기"""
    timestamp = request.args.get('timestamp')
    if not timestamp:
        return jsonify({'error': '타임스탬프가 필요합니다'}), 400
    
    # 타임스탬프로 해당하는 분석 파일 검색
    analysis_file = None
    for filename in os.listdir(Config.OUTPUT_DIR):
        if filename.startswith('analysis_') and filename.endswith('.json'):
            # 파일명에서 타임스탬프 부분 추출
            file_parts = filename.replace('analysis_', '').replace('.json', '').split('_')
            if len(file_parts) >= 3:  # [장비명, 날짜, 시간] 형태
                file_timestamp = f"{file_parts[-2]}_{file_parts[-1]}"
                if file_timestamp == timestamp:
                    analysis_file = os.path.join(Config.OUTPUT_DIR, filename)
                    break
    
    if not analysis_file:
        return jsonify({'error': '해당 타임스탬프의 분석 결과를 찾을 수 없습니다'}), 404
    
    try:
        with open(analysis_file, 'r') as f:
            analysis_data = json.load(f)
        return jsonify(analysis_data)
    except Exception as e:
        logger.error(f"분석 데이터 로드 오류: {e}")
        return jsonify({'error': '분석 데이터를 로드하는 중 오류가 발생했습니다'}), 500

@app.route('/policies')
@login_required
def view_policies():
    """정책 추천 보기"""
    timestamp = request.args.get('timestamp')
    
    if timestamp:
        # 특정 분석의 정책 불러오기
        analysis = load_analysis_result(timestamp)
        if analysis and 'policies' in analysis:
            return render_template('policies.html', 
                                  policies=analysis['policies'],
                                  timestamp=timestamp)
    
    # 현재 분석 결과가 있으면 표시
    if global_state['policies']:
        return render_template('policies.html', 
                              policies=global_state['policies'])
    
    # 정책이 없을 경우 대시보드로 리디렉션
    return redirect(url_for('index'))

@app.route('/config')
@login_required
def view_config():
    """생성된 Juniper 설정 보기"""
    timestamp = request.args.get('timestamp')
    
    if timestamp:
        # 특정 분석의 설정 불러오기
        analysis = load_analysis_result(timestamp)
        if analysis and 'config' in analysis:
            return render_template('config.html', 
                                  config=analysis['config'],
                                  timestamp=timestamp)
    
    # 현재 분석 결과가 있으면 표시
    if global_state['config']:
        return render_template('config.html', 
                              config=global_state['config'])
    
    # 설정이 없을 경우 대시보드로 리디렉션
    return redirect(url_for('index'))

@app.route('/syslog', methods=['GET', 'POST'])
@login_required
def manage_syslog():
    """Syslog 서버 관리"""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'start':
            # 서버 시작
            try:
                if global_state['is_syslog_running']:
                    return jsonify({'error': 'Syslog 서버가 이미 실행 중입니다'}), 400
                
                # 설정 가져오기
                host = request.form.get('host', '0.0.0.0')
                port = int(request.form.get('port', 514))
                interval = int(request.form.get('interval', 3600))
                device_filter = request.form.get('device_filter', '')
                device_filter_type = request.form.get('device_filter_type', 'all')
                regex_filter = request.form.get('regex_filter', '')
                regex_filter_type = request.form.get('regex_filter_type', 'include')
                
                # 설정 저장
                global_state['syslog_config'].update({
                    'host': host,
                    'port': port,
                    'interval': interval,
                    'device_filter': device_filter,
                    'device_filter_type': device_filter_type,
                    'regex_filter': regex_filter,
                    'regex_filter_type': regex_filter_type
                })
                
                # 설정 영구 저장
                settings_dict = {
                    'dbscan_params': global_state['dbscan_params'],
                    'output_dir': Config.OUTPUT_DIR,
                    'syslog_config': global_state['syslog_config']
                }
                save_system_settings(settings_dict)
                
                # Syslog 서버 시작
                start_syslog_server()
                
                return jsonify({'success': True})
            except Exception as e:
                logger.error(f"Syslog server error: {e}")
                return jsonify({'error': f'Syslog 서버 오류: {str(e)}'}), 500

        elif action == 'stop':
            # 서버 중지
            if not global_state['is_syslog_running']:
                return jsonify({'error': 'Syslog 서버가 실행 중이 아닙니다'}), 400

            stop_syslog_server()
            return jsonify({'success': True})

    # GET 메서드는 설정 페이지 표시
    return render_template('syslog.html',
                          is_running=global_state['is_syslog_running'],
                          syslog_config=global_state['syslog_config'])

@app.route('/api/log_files')
@login_required
def api_log_files():
    """로그 파일 목록 API"""
    log_type = request.args.get('type', 'upload')

    # 기존 함수 재사용
    logs = get_logs_list(log_type)

    # 응답 형태 맞추기
    files = []
    for log in logs:
        files.append({
            'filename': log['filename'],
            'size': log['size'],
            'modified': log['modified'].isoformat() if hasattr(log['modified'], 'isoformat') else str(log['modified'])
        })

    return jsonify({
        'success': True,
        'files': files
    })

@app.route('/api/system_logs')
@login_required
def api_system_logs():
    """시스템 로그 파일 내용 반환 API"""
    try:
        # 로그 파일 경로
        log_file = "firewall_recommender.log"

        # 표시할 최대 라인 수 (옵션으로 쿼리 파라미터로 받을 수 있음)
        max_lines = request.args.get('max_lines', 50, type=int)

        # 로그 파일이 존재하는지 확인
        if not os.path.exists(log_file):
            return jsonify({'error': '로그 파일을 찾을 수 없습니다.'}), 404

        # 파일의 마지막 N 라인 읽기 (tail 기능)
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            # 마지막 max_lines 개수만큼만 가져오기
            log_content = lines[-max_lines:] if len(lines) > max_lines else lines

        return jsonify({'success': True, 'log_content': log_content})

    except Exception as e:
        logger.error(f"로그 파일 읽기 오류: {e}")
        return jsonify({'error': f'로그 파일을 읽는 중 오류가 발생했습니다: {str(e)}'}), 500

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """시스템 설정"""
    if request.method == 'POST':
        try:
            # DBSCAN 파라미터 업데이트
            global_state['dbscan_params'].update({
                'min_occurrences': int(request.form.get('min_occurrences', 1)),
                'eps': float(request.form.get('eps', 0.5)),
                'min_samples': int(request.form.get('min_samples', 2)),
                'max_data_points': int(request.form.get('max_data_points', 10000))
            })

            # Syslog 설정 업데이트
            global_state['syslog_config'].update({
                'host': request.form.get('syslog_host', global_state['syslog_config']['host']),
                'port': int(request.form.get('syslog_port', global_state['syslog_config']['port'])),
                'interval': int(request.form.get('syslog_interval', global_state['syslog_config']['interval']))
            })
            
            # 기타 설정 업데이트 (디렉토리 등)
            Config.OUTPUT_DIR = request.form.get('output_dir', Config.OUTPUT_DIR)
            retention_days = int(request.form.get('retention_days', 30))
            
            # 설정 저장 - Syslog 설정도 함께 저장
            settings_dict = {
                'dbscan_params': global_state['dbscan_params'],
                'output_dir': Config.OUTPUT_DIR,
                'retention_days': retention_days,
                'syslog_config': global_state['syslog_config']
            }
            
            save_system_settings(settings_dict)
            
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'error': str(e)}), 400
    
    # GET 메서드는 설정 페이지 표시
    return render_template('settings.html',
                          dbscan_params=global_state['dbscan_params'],
                          output_dir=Config.OUTPUT_DIR,
                          syslog_config=global_state['syslog_config'])

@app.route('/api/system_info')
@login_required
def api_system_info():
    """시스템 정보 반환"""
    import psutil
    
    try:
        # 디스크 사용량
        disk_usage = psutil.disk_usage(Config.BASE_DIR)
        disk_usage_str = f"{disk_usage.used / (1024**3):.1f}GB / {disk_usage.total / (1024**3):.1f}GB ({disk_usage.percent}%)"
        
        # 메모리 사용량
        memory = psutil.virtual_memory()
        memory_usage_str = f"{memory.used / (1024**3):.1f}GB / {memory.total / (1024**3):.1f}GB ({memory.percent}%)"
        
        return jsonify({
            'success': True,
            'disk_usage': disk_usage_str,
            'memory_usage': memory_usage_str
        })
    except Exception as e:
        logger.error(f"시스템 정보 조회 오류: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/cleanup', methods=['POST'])
@login_required
def api_cleanup():
    """오래된 데이터 정리"""
    try:
        retention_days = int(request.form.get('retention_days', 30))
        if retention_days < 1:
            return jsonify({'success': False, 'error': '보관 일수는 1일 이상이어야 합니다'})
        
        # 파일 정리 로직 구현
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        deleted_count = 0
        
        # 출력 디렉토리 정리
        for filename in os.listdir(Config.OUTPUT_DIR):
            file_path = os.path.join(Config.OUTPUT_DIR, filename)
            if os.path.isfile(file_path):
                file_mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                if file_mtime < cutoff_date:
                    os.remove(file_path)
                    deleted_count += 1
        
        # 로그 디렉토리 정리
        for filename in os.listdir(Config.LOGS_DIR):
            file_path = os.path.join(Config.LOGS_DIR, filename)
            if os.path.isfile(file_path):
                file_mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                if file_mtime < cutoff_date:
                    os.remove(file_path)
                    deleted_count += 1
        
        return jsonify({
            'success': True,
            'message': f'{deleted_count}개의 파일이 삭제되었습니다.'
        })
    except Exception as e:
        logger.error(f"데이터 정리 오류: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/analyze_syslog_file', methods=['POST'])
@login_required
def api_analyze_syslog_file():
    """개별 Syslog 파일 분석 API 엔드포인트"""
    filename = request.form.get('filename')
    
    if not filename:
        return jsonify({'error': '파일명이 지정되지 않았습니다'}), 400
    
    # 파일 경로 구성
    log_file_path = os.path.join(Config.LOGS_DIR, filename)
    
    # 파일 존재 확인
    if not os.path.exists(log_file_path):
        return jsonify({'error': '지정된 파일을 찾을 수 없습니다'}), 404
    
    # 분석 파라미터 가져오기
    params = {
        'min_occurrences': int(request.form.get('min_occurrences', 1)),
        'eps': float(request.form.get('eps', 0.5)),
        'min_samples': int(request.form.get('min_samples', 2)),
        'max_data_points': int(request.form.get('max_data_points', 10000))
    }

    # 필터 파라미터 가져오기
    filters = get_filter_params_from_request(request.form)

    # top_n 파라미터 가져오기
    top_n = int(request.form.get('top_n', 50))

    try:
        # 로그 파싱
        parser = LogParser(log_files=[log_file_path])
        log_df = parser.process_logs()

        if log_df.empty:
            return jsonify({'error': '유효한 로그 데이터를 찾을 수 없습니다'}), 400

        # 필터링 적용
        filtered_df = apply_filters(log_df, filters)

        if filtered_df.empty:
            return jsonify({'error': '필터링 후 남은 로그 데이터가 없습니다. 필터 조건을 완화해 주세요.'}), 400

        # 트래픽 분석
        analyzer = TrafficAnalyzer(filtered_df, **params)
        analyzer.cluster_traffic_patterns()

        # 분석 결과 (상위 트래픽 패턴, 클러스터링 등)
        top_traffic_df = analyzer.analyze_top_traffic_patterns(top_n=top_n, subnet_grouping='/32')
        policies = analyzer.generate_policy_recommendations()
        config = PolicyGenerator(policies).generate_juniper_config()

        # 시각화 생성
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        visualizations = create_visualizations(analyzer, timestamp)

        # 장비명 정보 수집 - 로그 내용에서만 추출
        device_names = []
        if 'device_name' in filtered_df.columns:
            log_device_names = list(filtered_df['device_name'].unique())
            # 'unknown'이 아닌 유효한 장비명만 필터링
            device_names = [name for name in log_device_names if name and name.strip() != 'unknown']
        
        # 장비명이 없는 경우 기본값 설정
        if not device_names:
            device_names = ['Unknown_Device']
            logger.warning(f"로그에서 유효한 장비명을 찾을 수 없습니다. 파일: {filename}")
        
        logger.info(f"단일 파일 분석 - 로그에서 추출된 장비명: {device_names}")

        # 필터 적용 여부 확인
        filters_applied = any([
            filters.get('device_name_filter') and filters.get('device_name_filter').strip(),
            filters.get('source_ip_filter') and filters.get('source_ip_filter').strip(),
            filters.get('destination_ip_filter') and filters.get('destination_ip_filter').strip(),
            filters.get('port_filter') and filters.get('port_filter').strip(),
            filters.get('protocol_filter') and filters.get('protocol_filter').strip(),
            filters.get('source_zone_filter') and filters.get('source_zone_filter').strip(),
            filters.get('destination_zone_filter') and filters.get('destination_zone_filter').strip(),
            filters.get('exclude_noise')
        ])

        # 로그 파일명만 추출 (경로 제외)
        log_filenames = [filename]

        # 분석 결과 저장
        save_analysis_results(timestamp, {
            'params': params,
            'filters': filters,
            'policies': policies,
            'config': config,
            'top_traffic': top_traffic_df.to_dict('records') if top_traffic_df is not None else [],
            'visualizations': visualizations,
            'source': 'syslog',
            'log_files': [log_file_path],
            'log_filenames': log_filenames,
            'device_names': device_names,  # 로그에서만 추출된 장비명
            'filters_applied': filters_applied,
            'total_log_records': len(log_df),
            'filtered_log_records': len(filtered_df),
            'analysis_type': 'single_file',
            'source_filename': filename
        })

        # 전역 상태 업데이트
        global_state['analyzer'] = analyzer
        global_state['log_df'] = filtered_df
        global_state['policies'] = policies
        global_state['config'] = config

        logger.info(f"단일 Syslog 파일 분석 완료: {filename} -> {len(policies)}개 정책 생성")

        return jsonify({
            'success': True,
            'policies_count': len(policies),
            'timestamp': timestamp,
            'visualizations': visualizations,
            'filename': filename,
            'device_names': device_names,
            'message': f'파일 "{filename}" 분석이 완료되었습니다.'
        })

    except Exception as e:
        logger.error(f"단일 Syslog 파일 분석 오류: {e}", exc_info=True)
        return jsonify({'error': f'분석 중 오류가 발생했습니다: {str(e)}'}), 500

@app.route('/visualization/<path:filename>')
def serve_visualization(filename):
    """시각화 파일 제공 (국가별, ASN별 포함)"""
    # 실제 파일 경로 구성
    full_path = os.path.join(Config.OUTPUT_DIR, filename)
    
    # 파일이 존재하면 그대로 전송
    if os.path.exists(full_path):
        return send_file(full_path)
    
    # 동적 HTML 생성을 위한 정보 추출
    viz_type = "데이터 시각화"
    ip_version = "IPv4"
    analysis_type = "일반"
    
    # 파일명에서 정보 추출
    if '_ipv6.html' in filename:
        ip_version = "IPv6"
    
    if 'sankey_country' in filename:
        viz_type = "국가별 트래픽 흐름"
        analysis_type = "국가별"
    elif 'sankey_asn' in filename:
        viz_type = "ASN별 트래픽 흐름"  
        analysis_type = "ASN별"
    elif 'sankey' in filename:
        viz_type = "Sankey 다이어그램"
        analysis_type = "IP별"
    elif '3d_interactive' in filename:
        viz_type = "3D 트래픽 시각화"
        analysis_type = "3D"
    
    # 동적 HTML 생성
    html_content = f"""
    <!DOCTYPE html>
    <html lang="ko" data-bs-theme="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{ip_version} {analysis_type} 분석 - 데이터 없음</title>
        <link rel="stylesheet" href="/static/css/bootstrap.min.css">
        <link rel="stylesheet" href="/static/css/bootstrap-icons.css">
        <style>
            body {{
                background-color: #121212 !important;
                color: #e0e0e0;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            }}
            .card {{
                background-color: #1e1e1e;
                border-color: #333;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
            }}
            .card-header {{
                background: linear-gradient(135deg, #1a1a2e, #16213e);
                border-bottom-color: #333;
            }}
            .info-icon {{
                font-size: 64px;
                background: linear-gradient(135deg, #667eea, #764ba2);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }}
            .feature-badge {{
                background: linear-gradient(135deg, #667eea, #764ba2);
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 20px;
                font-weight: 500;
                font-size: 0.9rem;
            }}
            .suggestion-list {{
                background-color: #1a1a1a;
                border-radius: 8px;
                padding: 20px;
                margin-top: 20px;
            }}
            .suggestion-item {{
                display: flex;
                align-items: center;
                margin-bottom: 12px;
                padding: 8px;
                border-radius: 6px;
                transition: background-color 0.2s;
            }}
            .suggestion-item:hover {{
                background-color: #2d2d2d;
            }}
            .suggestion-icon {{
                margin-right: 12px;
                color: #667eea;
            }}
        </style>
    </head>
    <body class="d-flex justify-content-center align-items-center" style="min-height: 100vh; padding: 20px;">
        <div class="container" style="max-width: 600px;">
            <div class="card shadow-lg">
                <div class="card-header text-center">
                    <h4 class="mb-0 text-white">
                        <i class="bi bi-{"globe" if "country" in analysis_type.lower() else "building" if "asn" in analysis_type.lower() else "diagram-3"} me-2"></i>
                        {ip_version} {viz_type}
                    </h4>
                    <span class="feature-badge mt-2">
                        {"🌍 GeoIP 기반" if analysis_type in ["국가별", "ASN별"] else "📊 트래픽 분석"}
                    </span>
                </div>
                <div class="card-body text-center p-4">
                    <div class="info-icon mb-3">
                        <i class="bi bi-info-circle"></i>
                    </div>
                    <h5 class="mb-3">{ip_version} {analysis_type} 데이터가 없습니다</h5>
                    
                    <div class="alert alert-info border-0" style="background-color: rgba(13, 202, 240, 0.1); border-left: 4px solid #0dcaf0;">
                        <p class="mb-2">현재 분석 결과에는 {ip_version} {analysis_type} 트래픽 데이터가 포함되어 있지 않습니다.</p>
                        <small class="text-muted">
                            {"다른 IP 버전의 데이터만 있거나 해당 트래픽이 분석되지 않았을 수 있습니다." if ip_version == "IPv6" else "IPv6 트래픽이 없거나 필터링되었을 수 있습니다."}
                        </small>
                    </div>
                    
                    <div class="suggestion-list">
                        <h6 class="text-light mb-3"><i class="bi bi-lightbulb me-2"></i>해결 방법</h6>
                        
                        <div class="suggestion-item">
                            <i class="bi bi-check-circle suggestion-icon"></i>
                            <span>다른 IP 버전 탭을 확인해보세요</span>
                        </div>
                        
                        <div class="suggestion-item">
                            <i class="bi bi-funnel suggestion-icon"></i>
                            <span>분석 필터 설정을 다시 확인해보세요</span>
                        </div>
                        
                        {"<div class='suggestion-item'><i class='bi bi-database suggestion-icon'></i><span>GeoIP 데이터베이스가 정상적으로 로드되었는지 확인하세요</span></div>" if analysis_type in ["국가별", "ASN별"] else ""}
                        
                        <div class="suggestion-item">
                            <i class="bi bi-arrow-clockwise suggestion-icon"></i>
                            <span>새로운 로그 데이터로 다시 분석해보세요</span>
                        </div>
                    </div>
                    
                    <div class="mt-4">
                        <button onclick="window.parent.history.back()" class="btn btn-outline-light me-2">
                            <i class="bi bi-arrow-left me-1"></i>이전으로
                        </button>
                        <button onclick="window.parent.location.reload()" class="btn btn-primary">
                            <i class="bi bi-arrow-clockwise me-1"></i>새로고침
                        </button>
                    </div>
                </div>
            </div>
        </div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """
    
    # 응답 생성 및 반환
    response = make_response(html_content)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['Cache-Control'] = 'max-age=3600'  # 1시간 캐싱
    return response 

@app.route('/api/traffic_patterns', methods=['POST'])
@login_required
def api_traffic_patterns():
    """실시간 트래픽 패턴 분석 API (서브넷 그룹핑 옵션 지원)"""
    try:
        timestamp = request.form.get('timestamp')
        subnet_grouping = request.form.get('subnet_grouping', '/32')
        top_n = int(request.form.get('top_n', 100))
        
        if not timestamp:
            return jsonify({'error': '타임스탬프가 필요합니다'}), 400
        
        # 분석 결과 로드
        analysis_result = load_analysis_result(timestamp)
        if not analysis_result:
            return jsonify({'error': '해당 타임스탬프의 분석 결과를 찾을 수 없습니다'}), 404
        
        # 로그 파일 경로 확인
        log_files = analysis_result.get('log_files', [])
        if not log_files:
            return jsonify({'error': '원본 로그 파일 정보가 없습니다'}), 400
        
        # 로그 파일 존재 확인
        existing_files = [f for f in log_files if os.path.exists(f)]
        if not existing_files:
            return jsonify({'error': '원본 로그 파일을 찾을 수 없습니다'}), 400
        
        # 기존 필터 설정 가져오기
        filters = analysis_result.get('filters', {})
        
        # 로그 재파싱
        parser = LogParser(log_files=existing_files)
        log_df = parser.process_logs()
        
        if log_df.empty:
            return jsonify({'error': '유효한 로그 데이터가 없습니다'}), 400
        
        # 필터 적용
        filtered_df = apply_filters(log_df, filters)
        
        if filtered_df.empty:
            return jsonify({'error': '필터링 후 남은 데이터가 없습니다'}), 400
        
        # 기존 분석 파라미터 사용
        params = analysis_result.get('params', {
            'min_occurrences': 1,
            'eps': 0.5,
            'min_samples': 2,
            'max_data_points': 10000
        })
        
        # 트래픽 분석기 생성
        analyzer = TrafficAnalyzer(filtered_df, **params)
        analyzer.cluster_traffic_patterns()
        
        # 새로운 서브넷 그룹핑으로 상위 트래픽 분석
        top_traffic_df = analyzer.analyze_top_traffic_patterns(
            top_n=top_n, 
            subnet_grouping=subnet_grouping
        )
        
        if top_traffic_df is None or top_traffic_df.empty:
            return jsonify({'traffic_patterns': [], 'subnet_grouping': subnet_grouping})
        
        # 결과를 딕셔너리로 변환
        traffic_patterns = top_traffic_df.to_dict('records')
        
        return jsonify({
            'success': True,
            'traffic_patterns': traffic_patterns,
            'subnet_grouping': subnet_grouping,
            'total_patterns': len(traffic_patterns)
        })
        
    except Exception as e:
        logger.error(f"트래픽 패턴 분석 API 오류: {e}", exc_info=True)
        return jsonify({'error': f'분석 중 오류가 발생했습니다: {str(e)}'}), 500

#----- 유틸리티 함수 -----#

def get_filter_params_from_request(form_data):
    """요청 데이터에서 필터 파라미터 추출"""
    return {
        'device_name_filter': form_data.get('device_name_filter', ''),
        'device_name_filter_type': form_data.get('device_name_filter_type', 'include'),
        'source_ip_filter': form_data.get('source_ip_filter', ''),
        'source_ip_filter_type': form_data.get('source_ip_filter_type', 'include'),
        'destination_ip_filter': form_data.get('destination_ip_filter', ''),
        'destination_ip_filter_type': form_data.get('destination_ip_filter_type', 'include'),
        'port_filter': form_data.get('port_filter', ''),
        'port_filter_type': form_data.get('port_filter_type', 'include'),
        'protocol_filter': form_data.get('protocol_filter', ''),
        'protocol_filter_type': form_data.get('protocol_filter_type', 'include'),
        'source_zone_filter': form_data.get('source_zone_filter', ''),
        'source_zone_filter_type': form_data.get('source_zone_filter_type', 'include'),
        'destination_zone_filter': form_data.get('destination_zone_filter', ''),
        'destination_zone_filter_type': form_data.get('destination_zone_filter_type', 'include'),
        'policy_name_filter': form_data.get('policy_name_filter', ''),  # 정책명 필터 추가
        'policy_name_filter_type': form_data.get('policy_name_filter_type', 'include'),  # 정책명 필터 타입 추가
        'start_date': form_data.get('start_date', ''),
        'end_date': form_data.get('end_date', ''),
        'exclude_noise': form_data.get('exclude_noise') == '1'
    }

def apply_filters(log_df, filters):
    """필터를 로그 데이터에 적용"""
    filtered_df = log_df.copy()
    
    # IP 주소 매칭 헬퍼 함수 - CIDR 및 정확한 매칭 지원
    def ip_matches(ip, filter_list):
        try:
            # IP를 ipaddress 객체로 변환
            target_ip = ipaddress.ip_address(ip)
            
            for filter_ip in filter_list:
                if '/' in filter_ip:  # CIDR 표기법
                    try:
                        network = ipaddress.ip_network(filter_ip, strict=False)
                        if target_ip in network:
                            return True
                    except ValueError:
                        # 정확한 문자열 매칭으로 폴백
                        if filter_ip == ip:
                            return True
                else:  # 단일 IP
                    try:
                        filter_ip_obj = ipaddress.ip_address(filter_ip)
                        if target_ip == filter_ip_obj:
                            return True
                    except ValueError:
                        # IP 변환 오류 시 정확한 문자열 비교
                        if filter_ip == ip:
                            return True
            return False
        except ValueError:
            # IP 변환 오류 시 정확한 문자열 매칭
            return ip in filter_list

    # 장비명 필터
    if filters.get('device_name_filter') and filters.get('device_name_filter').strip():
        device_filter = filters['device_name_filter']
        filter_type = filters['device_name_filter_type']

        device_list = [device.strip() for device in device_filter.split(',') if device.strip()]

        if device_list:
            if filter_type == 'include':
                filtered_df = filtered_df[filtered_df['device_name'].isin(device_list)]
            elif filter_type == 'exclude':
                filtered_df = filtered_df[~filtered_df['device_name'].isin(device_list)]

    # 출발지 IP 필터
    if filters.get('source_ip_filter') and filters.get('source_ip_filter').strip():
        source_ip_filter = filters['source_ip_filter']
        filter_type = filters['source_ip_filter_type']

        ip_list = [ip.strip() for ip in source_ip_filter.split(',') if ip.strip()]

        if ip_list:
            # 향상된 IP 매칭 사용
            mask = filtered_df['source_ip'].apply(lambda ip: ip_matches(ip, ip_list))

            if filter_type == 'include':
                filtered_df = filtered_df[mask]
            elif filter_type == 'exclude':
                filtered_df = filtered_df[~mask]

    # 목적지 IP 필터
    if filters.get('destination_ip_filter') and filters.get('destination_ip_filter').strip():
        dest_ip_filter = filters['destination_ip_filter']
        filter_type = filters['destination_ip_filter_type']

        ip_list = [ip.strip() for ip in dest_ip_filter.split(',') if ip.strip()]

        if ip_list:
            # 향상된 IP 매칭 사용
            mask = filtered_df['destination_ip'].apply(lambda ip: ip_matches(ip, ip_list))

            if filter_type == 'include':
                filtered_df = filtered_df[mask]
            elif filter_type == 'exclude':
                filtered_df = filtered_df[~mask]

    # 포트 필터 - 대규모 범위 처리 개선
    if filters.get('port_filter') and filters.get('port_filter').strip():
        port_filter = filters['port_filter']
        filter_type = filters['port_filter_type']

        # 포트 범위 효율적 처리
        def port_in_ranges(port, port_ranges):
            for p_range in port_ranges:
                if '-' in p_range:
                    start, end = map(int, p_range.split('-'))
                    if start <= port <= end:
                        return True
                else:
                    if port == int(p_range):
                        return True
            return False

        port_ranges = [p.strip() for p in port_filter.split(',') if p.strip()]

        if port_ranges:
            # 범위 검사 함수를 사용하여 각 포트 확인
            mask = (
                filtered_df['source_port'].apply(lambda p: port_in_ranges(p, port_ranges)) | 
                filtered_df['destination_port'].apply(lambda p: port_in_ranges(p, port_ranges))
            )

            if filter_type == 'include':
                filtered_df = filtered_df[mask]
            elif filter_type == 'exclude':
                filtered_df = filtered_df[~mask]

    # 프로토콜 필터
    if filters.get('protocol_filter') and filters.get('protocol_filter').strip():
        protocol_filter = filters['protocol_filter']
        filter_type = filters['protocol_filter_type']

        protocol_list = [p.strip().lower() for p in protocol_filter.split(',') if p.strip()]

        if protocol_list:
            # 대소문자 구분 없이 정확한 프로토콜 매칭
            mask = filtered_df['protocol'].str.lower().isin(protocol_list)

            if filter_type == 'include':
                filtered_df = filtered_df[mask]
            elif filter_type == 'exclude':
                filtered_df = filtered_df[~mask]

    # 정책명 필터 추가
    if filters.get('policy_name_filter'):
        policy_filter = filters['policy_name_filter']
        filter_type = filters['policy_name_filter_type']

        policy_list = [p.strip() for p in policy_filter.split(',') if p.strip()]

        if policy_list and 'policy_name' in filtered_df.columns:
            mask = filtered_df['policy_name'].isin(policy_list)

            if filter_type == 'include':
                filtered_df = filtered_df[mask]
            elif filter_type == 'exclude':
                filtered_df = filtered_df[~mask]

    # 존 필터 구현
    if filters.get('source_zone_filter') and filters.get('source_zone_filter').strip():
        zone_filter = filters['source_zone_filter']
        filter_type = filters['source_zone_filter_type']

        zone_list = [z.strip() for z in zone_filter.split(',') if z.strip()]

        if zone_list and 'source_zone' in filtered_df.columns:
            mask = filtered_df['source_zone'].isin(zone_list)

            if filter_type == 'include':
                filtered_df = filtered_df[mask]
            elif filter_type == 'exclude':
                filtered_df = filtered_df[~mask]

    if filters.get('destination_zone_filter') and filters.get('destination_zone_filter').strip():
        zone_filter = filters['destination_zone_filter']
        filter_type = filters['destination_zone_filter_type']

        zone_list = [z.strip() for z in zone_filter.split(',') if z.strip()]

        if zone_list and 'destination_zone' in filtered_df.columns:
            mask = filtered_df['destination_zone'].isin(zone_list)

            if filter_type == 'include':
                filtered_df = filtered_df[mask]
            elif filter_type == 'exclude':
                filtered_df = filtered_df[~mask]

    # 날짜 필터
    if filters.get('start_date') and filters.get('end_date'):
        try:
            start_date = pd.to_datetime(filters['start_date'])
            end_date = pd.to_datetime(filters['end_date'])
            
            # end_date는 해당 날짜의 마지막 시간까지 포함
            end_date = end_date + pd.Timedelta(days=1) - pd.Timedelta(seconds=1)

            if 'timestamp' in filtered_df.columns:
                # timestamp 열의 타입 확인
                if not pd.api.types.is_datetime64_any_dtype(filtered_df['timestamp']):
                    filtered_df['timestamp'] = pd.to_datetime(filtered_df['timestamp'])
                
                filtered_df = filtered_df[(filtered_df['timestamp'] >= start_date) &
                                         (filtered_df['timestamp'] <= end_date)]
        except Exception as e:
            logger.error(f"날짜 필터 적용 오류: {e}")

    # 노이즈 제외 옵션
    if filters.get('exclude_noise'):
        if 'cluster' in filtered_df.columns:
            # 클러스터가 -1인 경우 노이즈 포인트
            filtered_df = filtered_df[filtered_df['cluster'] != -1]

    return filtered_df

def create_visualizations(analyzer, timestamp):
    """시각화 생성 (Sankey, 3D 등)"""
    visualizations = {}
    
    # 타임스탬프 형식이 YYYYMMDD_HHMMSS인지 확인하고 필요시 변환
    if '_' not in timestamp:
        # 형식이 다르면 언더스코어 추가
        date_part = timestamp[:8]
        time_part = timestamp[8:] if len(timestamp) > 8 else ''
        timestamp = f"{date_part}_{time_part}"
    
    # Sankey 다이어그램
    sankey_prefix = os.path.join(Config.OUTPUT_DIR, f"traffic_sankey_{timestamp}")
    sankey_files = analyzer.visualize_traffic_sankey(sankey_prefix)
    visualizations['sankey'] = sankey_files

    # 국가별 Sankey 다이어그램
    try:
        country_sankey_prefix = os.path.join(Config.OUTPUT_DIR, f"traffic_sankey_country_{timestamp}")
        country_sankey_files = analyzer.visualize_traffic_sankey_by_country(country_sankey_prefix)
        visualizations['sankey_country'] = country_sankey_files
        logger.info("국가별 Sankey 다이어그램 생성 완료")
    except Exception as e:
        logger.error(f"국가별 Sankey 다이어그램 생성 오류: {e}")
        visualizations['sankey_country'] = {}
    
    # ASN별 Sankey 다이어그램
    try:
        asn_sankey_prefix = os.path.join(Config.OUTPUT_DIR, f"traffic_sankey_asn_{timestamp}")
        asn_sankey_files = analyzer.visualize_traffic_sankey_by_asn(asn_sankey_prefix)
        visualizations['sankey_asn'] = asn_sankey_files
        logger.info("ASN별 Sankey 다이어그램 생성 완료")
    except Exception as e:
        logger.error(f"ASN별 Sankey 다이어그램 생성 오류: {e}")
        visualizations['sankey_asn'] = {}
    
    # 3D 시각화
    viz_prefix = os.path.join(Config.OUTPUT_DIR, f"traffic_3d_interactive_{timestamp}")
    interactive_3d_files = analyzer.visualize_traffic_patterns_3d_interactive(viz_prefix)
    visualizations['interactive_3d'] = interactive_3d_files

    return visualizations

def save_analysis_results(timestamp, data):
    """분석 결과 저장"""
    import numpy as np
    from json import JSONEncoder

    # NumPy 타입을 처리하는 커스텀 인코더
    class NumpyEncoder(JSONEncoder):
        def default(self, obj):
            if isinstance(obj, np.integer):
                return int(obj)
            elif isinstance(obj, np.floating):
                return float(obj)
            elif isinstance(obj, np.ndarray):
                return obj.tolist()
            elif isinstance(obj, np.bool_):
                return bool(obj)
            return super().default(obj)

    os.makedirs(Config.OUTPUT_DIR, exist_ok=True)

    # 장비명 정보 추출 (첫 번째 장비명 또는 "All" 사용)
    device_name = "All"
    if 'device_names' in data and data['device_names']:
        device_name = data['device_names'][0]
    
    # 분석 메타데이터 저장 - 장비명 포함
    metadata_file = os.path.join(Config.OUTPUT_DIR, f"analysis_{device_name}_{timestamp}.json")
    with open(metadata_file, 'w') as f:
        json.dump(data, f, indent=2, cls=NumpyEncoder)
    
    logger.info(f"Analysis results saved to {metadata_file}")
    return metadata_file
    

def load_analysis_result(timestamp):
    """저장된 분석 결과 불러오기"""
    # 정확히 일치하는 파일명 먼저 확인
    metadata_file = os.path.join(Config.OUTPUT_DIR, f"analysis_{timestamp}.json")
    
    if os.path.exists(metadata_file):
        with open(metadata_file, 'r') as f:
            return json.load(f)
    
    # 일치하는 파일이 없으면 타임스탬프가 포함된 파일 검색
    for filename in os.listdir(Config.OUTPUT_DIR):
        if filename.startswith('analysis_') and filename.endswith('.json'):
            # 파일명에서 타임스탬프 부분 추출
            file_parts = filename.replace('analysis_', '').replace('.json', '').split('_')
            if len(file_parts) >= 3:  # [장비명, 날짜, 시간] 형태
                file_timestamp = f"{file_parts[-2]}_{file_parts[-1]}"
                if file_timestamp == timestamp:
                    file_path = os.path.join(Config.OUTPUT_DIR, filename)
                    with open(file_path, 'r') as f:
                        return json.load(f)
    
    # 타임스탬프 형식이 다를 수 있으므로 타임스탬프 부분 확인
    for filename in os.listdir(Config.OUTPUT_DIR):
        if filename.startswith('analysis_') and filename.endswith('.json'):
            if timestamp in filename:
                file_path = os.path.join(Config.OUTPUT_DIR, filename)
                with open(file_path, 'r') as f:
                    return json.load(f)
    
    return None

def get_analyses_list(source_type):
    """특정 타입(upload 또는 syslog)의 분석 결과 목록 가져오기"""
    analyses = []
    
    # 출력 디렉토리 내 metadata 파일 탐색
    for filename in os.listdir(Config.OUTPUT_DIR):
        if filename.startswith('analysis_') and filename.endswith('.json'):
            file_path = os.path.join(Config.OUTPUT_DIR, filename)
            
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                # source 필드가 일치하는 항목만 선택
                if data.get('source') == source_type:
                    # 파일명에서 타임스탬프 추출 - 수정된 부분
                    # 파일명 형식: analysis_장비명_날짜_시간.json
                    parts = filename.replace('analysis_', '').replace('.json', '').split('_')
                    
                    # 파일명에 날짜와 시간이 있는 경우 (최소 3개 부분이 있어야 함)
                    if len(parts) >= 3:
                        # 마지막 두 부분을 날짜와 시간으로 사용
                        date_part = parts[-2]  # YYYYMMDD 부분
                        time_part = parts[-1]  # HHMMSS 부분
                        timestamp = f"{date_part}_{time_part}"
                    else:
                        # 형식이 다른 경우 전체를 타임스탬프로 사용
                        timestamp = '_'.join(parts)
                    
                    # 분석 결과에서 실제 타임스탬프 사용 (더 정확함)
                    if 'timestamp' in data:
                        timestamp = data['timestamp']
                    
                    # 날짜와 시간 분리
                    timestamp_parts = timestamp.split('_')
                    if len(timestamp_parts) >= 2:
                        date_part = timestamp_parts[0]
                        time_part = timestamp_parts[1]
                    else:
                        date_part = timestamp[:8] if len(timestamp) >= 8 else ""
                        time_part = timestamp[9:] if len(timestamp) >= 15 else ""
                    
                    analyses.append({
                        'timestamp': timestamp,
                        'date': date_part,  # YYYYMMDD 부분
                        'time': time_part,  # HHMMSS 부분
                        'policies_count': len(data.get('policies', [])),
                        'file_path': file_path,
                        'log_filenames': data.get('log_filenames', []),
                        'device_names': data.get('device_names', []),
                        'filters_applied': data.get('filters_applied', False),
                        'total_records': data.get('total_log_records', 0),
                        'filtered_records': data.get('filtered_log_records', 0),
                        'analysis_type': data.get('analysis_type', 'auto'),
                        'source_filename': data.get('source_filename', '')
                    })
            except Exception as e:
                logger.error(f"분석 결과 로드 오류: {e}")
                continue
    
    # 최신 분석 결과가 먼저 오도록 정렬
    analyses.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return analyses

def get_logs_list(source_type):
    """특정 타입(upload 또는 syslog)의 로그 파일 목록 가져오기"""
    logs = []
    
    if source_type == 'upload':
        log_dir = Config.UPLOAD_DIR
    else:  # syslog
        log_dir = Config.LOGS_DIR
    
    # 디렉토리 탐색
    if os.path.exists(log_dir):
        for filename in os.listdir(log_dir):
            if filename.endswith('.log'):
                file_path = os.path.join(log_dir, filename)
                
                # 파일 정보
                stat = os.stat(file_path)
                logs.append({
                    'filename': filename,
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime),
                    'file_path': file_path
                })
    
    # 최신 파일이 먼저 오도록 정렬
    logs.sort(key=lambda x: x['modified'], reverse=True)
    
    return logs

def start_syslog_server():
    """Syslog 서버 시작"""
    import threading
    
    if global_state['is_syslog_running']:
        return
    
    config = global_state['syslog_config']
    
    # 서버 인스턴스 생성
    server = SyslogServer(
        host=config['host'],
        port=config['port'],
        log_dir=Config.LOGS_DIR,
        analysis_interval=config['interval'],
        output_dir=Config.OUTPUT_DIR,
        device_filter=config['device_filter'],
        device_filter_type=config['device_filter_type'],
        regex_filter=config['regex_filter'],
        regex_filter_type=config['regex_filter_type']
    )
    
    # 별도 스레드에서 실행
    def run_server():
        server.start()
    
    thread = threading.Thread(target=run_server)
    thread.daemon = True
    thread.start()
    
    # 상태 업데이트
    global_state['syslog_server'] = server
    global_state['syslog_thread'] = thread
    global_state['is_syslog_running'] = True
    
    logger.info(f"Syslog server started on {config['host']}:{config['port']}")

def stop_syslog_server():
    """Syslog 서버 중지"""
    if not global_state['is_syslog_running']:
        return
    
    # 서버 중지
    if global_state['syslog_server']:
        global_state['syslog_server'].running = False
    
    # 상태 업데이트
    global_state['is_syslog_running'] = False
    global_state['syslog_server'] = None
    global_state['syslog_thread'] = None
    
    logger.info("Syslog server stopped")

def main():
    """메인 함수"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="ML기반 방화벽 정책 추천 시스템"
    )
    
    parser.add_argument('--host', default='0.0.0.0', help='웹 서버 호스트 (기본: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=14000, help='웹 서버 포트 (기본: 14000)')
    parser.add_argument('--ssl-cert', default='ssl/cert.pem', help='SSL 인증서 파일 경로')
    parser.add_argument('--ssl-key', default='ssl/key.pem', help='SSL 키 파일 경로')
    parser.add_argument('--debug', action='store_true', help='디버그 모드 활성화')
    
    args = parser.parse_args()
    
    # SSL 처리
    ssl_context = None
    if os.path.exists(args.ssl_cert) and os.path.exists(args.ssl_key):
        try:
            # SSL 컨텍스트 생성
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(certfile=args.ssl_cert, keyfile=args.ssl_key)
            logger.info("SSL 인증서 로드 성공")
        except Exception as e:
            logger.error(f"SSL 설정 오류: {e}")
            ssl_context = None
    
    if ssl_context:
        # HTTPS 서버
        http_server = WSGIServer((args.host, args.port), app, ssl_context=ssl_context)
        logger.info(f"HTTPS 서버가 {args.host}:{args.port}에서 시작됩니다.")
    else:
        # HTTP 서버 (SSL 없음)
        http_server = WSGIServer((args.host, args.port), app)
        logger.warning(f"SSL 인증서가 없습니다. HTTP 서버가 {args.host}:{args.port}에서 시작됩니다.")
    
    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        logger.info("서버가 종료됩니다.")
    
    # 실행 중인 Syslog 서버 종료
    if global_state['is_syslog_running']:
        stop_syslog_server()

if __name__ == "__main__":
    main()
