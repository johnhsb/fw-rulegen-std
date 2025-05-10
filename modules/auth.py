#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
방화벽 정책 추천 시스템 - 인증 모듈
----------------------------------
사용자 인증 관련 기능을 제공합니다.
"""

import os
import json
import hashlib
import logging
from functools import wraps
from flask import session, redirect, url_for, request

logger = logging.getLogger(__name__)

def load_user_config(config_file='config/users.json'):
    """
    사용자 설정 파일에서 사용자 정보 로드
    
    Args:
        config_file (str): 사용자 정보가 저장된 JSON 파일 경로
        
    Returns:
        dict: 사용자명을 키로, 해시된 비밀번호를 값으로 하는 딕셔너리
    """
    users = {}
    
    try:
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = json.load(f)
                users = {user['username']: user['password'] for user in config.get('users', [])}
            logger.info(f"{len(users)}명의 사용자를 {config_file}에서 로드했습니다.")
        else:
            # 설정 파일이 없으면 기본 관리자 계정 생성
            admin_password = hash_password('admin')
            users = {'admin': admin_password}
            
            # 디렉토리 생성
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            
            # 기본 사용자 정보 저장
            with open(config_file, 'w') as f:
                json.dump({
                    'users': [
                        {'username': 'admin', 'password': admin_password}
                    ]
                }, f, indent=2)
                
            logger.warning(f"사용자 설정 파일을 찾을 수 없어 기본 관리자 계정을 생성했습니다: {config_file}")
            logger.warning("기본 계정: username=admin, password=admin")
    except Exception as e:
        logger.error(f"사용자 설정 로드 오류: {e}")
        
        # 오류 발생 시 기본 관리자 계정 사용
        users = {'admin': hash_password('admin')}
        logger.warning("기본 관리자 계정을 사용합니다: username=admin, password=admin")
    
    return users

def hash_password(password):
    """
    비밀번호를 SHA-256으로 해시
    
    Args:
        password (str): 해시할 비밀번호
        
    Returns:
        str: 해시된 비밀번호 (16진수 문자열)
    """
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    """
    로그인이 필요한 뷰에 적용하는 데코레이터
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

