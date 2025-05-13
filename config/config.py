#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
방화벽 정책 추천 시스템 - 기본 설정
----------------------------------
애플리케이션의 기본 설정 값을 정의합니다.
"""

import os
import tempfile
from datetime import timedelta

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
