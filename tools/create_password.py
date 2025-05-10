#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
로그인 계정용 패스워드 해시 생성기
"""
import hashlib
import sys

if len(sys.argv) < 2:
    print("사용법: python create_password.py <비밀번호>")
    sys.exit(1)

password = sys.argv[1]
hashed = hashlib.sha256(password.encode()).hexdigest()
print(f"원본 비밀번호: {password}")
print(f"해시된 비밀번호: {hashed}")
