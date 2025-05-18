#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
방화벽 정책 추천 시스템 - 기본 설정
----------------------------------
애플리케이션의 기본 설정 값을 정의합니다.
"""

import os
import json
import tempfile
import logging
from datetime import timedelta

# 로거 설정
logger = logging.getLogger(__name__)

class Config:
    """애플리케이션 기본 설정"""
    
    # 기본 경로 설정
    BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
    STATIC_DIR = os.path.join(BASE_DIR, 'static')
    UPLOAD_DIR = os.path.join(tempfile.gettempdir(), 'fw_rulegen_uploads')
    OUTPUT_DIR = os.path.join(STATIC_DIR, 'output')
    LOGS_DIR = os.path.join(BASE_DIR, 'logs')
    
    # 사용자 설정 파일
    USERS_CONFIG = os.path.join(BASE_DIR, 'config', 'users.json')
    SETTINGS_FILE = os.path.join(BASE_DIR, 'config', 'system_settings.json')
    
    # Flask 설정
    SECRET_KEY = os.urandom(24)
    MAX_CONTENT_LENGTH = 200 * 1024 * 1024  # 최대 200MB 업로드 제한
    
    # 세션 설정
    SESSION_TYPE = 'filesystem'
    SESSION_FILE_DIR = os.path.join(BASE_DIR, 'flask_sessions')
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_COOKIE_SECURE = True
    SESSION_SERIALIZATION_FORMAT = 'msgpack'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)

def save_system_settings(settings_dict):
    """시스템 설정을 파일에 저장"""
    settings_file = Config.SETTINGS_FILE
    os.makedirs(os.path.dirname(settings_file), exist_ok=True)
    
    try:
        with open(settings_file, 'w') as f:
            json.dump(settings_dict, f, indent=2)
        logger.info("시스템 설정이 저장되었습니다.")
        return True
    except Exception as e:
        logger.error(f"설정 저장 오류: {e}")
        return False

def load_system_settings():
    """저장된 시스템 설정 로드"""
    settings_file = Config.SETTINGS_FILE
    
    if not os.path.exists(settings_file):
        return {}
        
    try:
        with open(settings_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"설정 로드 오류: {e}")
        return {}
