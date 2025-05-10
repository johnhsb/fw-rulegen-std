#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
방화벽 정책 추천 시스템 - 사용자 관리 CLI 도구
--------------------------------------------
사용자 계정을 관리하는 명령줄 인터페이스 도구입니다.
"""

import os
import sys
import json
import argparse
import getpass
import hashlib
from pathlib import Path

# 사용자 설정 파일 경로
DEFAULT_CONFIG_PATH = 'config/users.json'

def hash_password(password):
    """비밀번호를 SHA-256으로 해시"""
    return hashlib.sha256(password.encode()).hexdigest()

def load_users(config_file):
    """사용자 설정 파일에서 사용자 정보 로드"""
    try:
        # 설정 파일이 존재하는지 확인
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = json.load(f)
                return config.get('users', [])
        else:
            print(f"[경고] 사용자 설정 파일을 찾을 수 없습니다: {config_file}")
            # 디렉토리 생성
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            # 빈 사용자 목록으로 초기화
            return []
    except Exception as e:
        print(f"[오류] 사용자 설정 로드 실패: {e}")
        return []

def save_users(config_file, users):
    """사용자 정보를 설정 파일에 저장"""
    try:
        with open(config_file, 'w') as f:
            json.dump({'users': users}, f, indent=2)
        print(f"[성공] 사용자 설정이 저장되었습니다: {config_file}")
        return True
    except Exception as e:
        print(f"[오류] 사용자 설정 저장 실패: {e}")
        return False

def list_users(args):
    """사용자 목록 출력"""
    users = load_users(args.config)
    
    if not users:
        print("등록된 사용자가 없습니다.")
        return
    
    print("\n사용자 목록:")
    print("=" * 50)
    print(f"{'사용자명':<20} {'관리자':<10}")
    print("-" * 50)
    
    for user in users:
        is_admin = user.get('is_admin', False)
        print(f"{user['username']:<20} {'예' if is_admin else '아니오':<10}")
    
    print("=" * 50)
    print(f"총 {len(users)}명의 사용자가 등록되어 있습니다.\n")

def add_user(args):
    """새 사용자 추가"""
    users = load_users(args.config)
    
    # 사용자 이름 지정 또는 입력 받기
    username = args.username
    if not username:
        username = input("추가할 사용자 이름: ")
    
    # 사용자명 중복 확인
    if any(user['username'] == username for user in users):
        print(f"[오류] 이미 존재하는 사용자명입니다: {username}")
        return False
    
    # 비밀번호 입력 받기
    password = args.password
    if not password:
        password = getpass.getpass("비밀번호: ")
        confirm_password = getpass.getpass("비밀번호 확인: ")
        
        if password != confirm_password:
            print("[오류] 비밀번호가 일치하지 않습니다.")
            return False
    
    # 관리자 권한 설정
    is_admin = args.admin
    
    # 새 사용자 추가
    new_user = {
        'username': username,
        'password': hash_password(password),
        'is_admin': is_admin
    }
    
    users.append(new_user)
    
    # 사용자 정보 저장
    if save_users(args.config, users):
        print(f"[성공] 사용자 '{username}'가 추가되었습니다.")
        return True
    
    return False

def delete_user(args):
    """사용자 삭제"""
    users = load_users(args.config)
    
    # 사용자 이름 지정 또는 입력 받기
    username = args.username
    if not username:
        username = input("삭제할 사용자 이름: ")
    
    # 사용자 찾기
    for i, user in enumerate(users):
        if user['username'] == username:
            # 삭제 확인
            if not args.force:
                confirm = input(f"사용자 '{username}'을(를) 삭제하시겠습니까? (y/N): ")
                if confirm.lower() != 'y':
                    print("사용자 삭제가 취소되었습니다.")
                    return False
            
            # 사용자 삭제
            del users[i]
            
            # 사용자 정보 저장
            if save_users(args.config, users):
                print(f"[성공] 사용자 '{username}'가 삭제되었습니다.")
                return True
            return False
    
    print(f"[오류] 사용자를 찾을 수 없습니다: {username}")
    return False

def change_password(args):
    """사용자 비밀번호 변경"""
    users = load_users(args.config)
    
    # 사용자 이름 지정 또는 입력 받기
    username = args.username
    if not username:
        username = input("비밀번호를 변경할 사용자 이름: ")
    
    # 사용자 찾기
    for i, user in enumerate(users):
        if user['username'] == username:
            # 새 비밀번호 입력 받기
            password = args.password
            if not password:
                password = getpass.getpass("새 비밀번호: ")
                confirm_password = getpass.getpass("새 비밀번호 확인: ")
                
                if password != confirm_password:
                    print("[오류] 비밀번호가 일치하지 않습니다.")
                    return False
            
            # 비밀번호 변경
            users[i]['password'] = hash_password(password)
            
            # 사용자 정보 저장
            if save_users(args.config, users):
                print(f"[성공] 사용자 '{username}'의 비밀번호가 변경되었습니다.")
                return True
            return False
    
    print(f"[오류] 사용자를 찾을 수 없습니다: {username}")
    return False

def init_admin(args):
    """관리자 계정 초기화"""
    users = load_users(args.config)
    
    # 이미 관리자가 있는지 확인
    admin_exists = any(user.get('is_admin', False) for user in users)
    
    if admin_exists and not args.force:
        print("[경고] 관리자 계정이 이미 존재합니다. 강제로 초기화하려면 --force 옵션을 사용하세요.")
        return False
    
    # 새 관리자 비밀번호
    password = args.password
    if not password:
        password = getpass.getpass("관리자 비밀번호: ")
        confirm_password = getpass.getpass("관리자 비밀번호 확인: ")
        
        if password != confirm_password:
            print("[오류] 비밀번호가 일치하지 않습니다.")
            return False
    
    # 기존 관리자 찾기
    admin_found = False
    for i, user in enumerate(users):
        if user['username'] == 'admin':
            users[i]['password'] = hash_password(password)
            users[i]['is_admin'] = True
            admin_found = True
            break
    
    # 관리자가 없으면 새로 추가
    if not admin_found:
        users.append({
            'username': 'admin',
            'password': hash_password(password),
            'is_admin': True
        })
    
    # 사용자 정보 저장
    if save_users(args.config, users):
        print("[성공] 관리자 계정이 초기화되었습니다.")
        return True
    
    return False

def main():
    # 명령줄 인자 파서 설정
    parser = argparse.ArgumentParser(
        description="방화벽 정책 추천 시스템 - 사용자 관리 도구"
    )
    
    parser.add_argument(
        "--config", 
        default=DEFAULT_CONFIG_PATH, 
        help=f"사용자 설정 파일 경로 (기본값: {DEFAULT_CONFIG_PATH})"
    )
    
    # 하위 명령어 설정
    subparsers = parser.add_subparsers(dest="command", help="명령어")
    
    # 사용자 목록 조회 명령어
    list_parser = subparsers.add_parser("list", help="사용자 목록 조회")
    
    # 사용자 추가 명령어
    add_parser = subparsers.add_parser("add", help="사용자 추가")
    add_parser.add_argument("--username", help="사용자 이름")
    add_parser.add_argument("--password", help="비밀번호 (미지정 시 입력 프롬프트)")
    add_parser.add_argument("--admin", action="store_true", help="관리자 권한 부여")
    
    # 사용자 삭제 명령어
    delete_parser = subparsers.add_parser("delete", help="사용자 삭제")
    delete_parser.add_argument("--username", help="사용자 이름")
    delete_parser.add_argument("--force", action="store_true", help="확인 없이 강제 삭제")
    
    # 비밀번호 변경 명령어
    passwd_parser = subparsers.add_parser("passwd", help="비밀번호 변경")
    passwd_parser.add_argument("--username", help="사용자 이름")
    passwd_parser.add_argument("--password", help="새 비밀번호 (미지정 시 입력 프롬프트)")
    
    # 관리자 초기화 명령어
    init_parser = subparsers.add_parser("init-admin", help="관리자 계정 초기화")
    init_parser.add_argument("--password", help="관리자 비밀번호 (미지정 시 입력 프롬프트)")
    init_parser.add_argument("--force", action="store_true", help="기존 관리자가 있어도 강제 초기화")
    
    # 명령줄 인자 파싱
    args = parser.parse_args()
    
    # 명령어에 따라 함수 실행
    if args.command == "list":
        list_users(args)
    elif args.command == "add":
        add_user(args)
    elif args.command == "delete":
        delete_user(args)
    elif args.command == "passwd":
        change_password(args)
    elif args.command == "init-admin":
        init_admin(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
