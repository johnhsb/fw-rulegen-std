#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Juniper 방화벽 로그 파싱 테스트 프로그램
"""

import re
import sys
from datetime import datetime

# 기존 정규식 패턴
ORIGINAL_PATTERN = re.compile(
    r'.*RT_FLOW: RT_FLOW_SESSION_(?:CREATE|CLOSE):' # 세션 시작/종료
#   r'(?:\s+session\s+closed\s+([\w\s]+):)?\s*' # 세션 종료 원인 (선택적)
    r'(?:\s+session\s+([a-zA-Z\s]+)):?\s*' # 세션 종료 원인 (선택적)
    r'([\d\.a-fA-F:]+)/(\d+)->([\d\.a-fA-F:]+)/(\d+)' # 첫 번째 IP 주소/포트 쌍
    r'\s+0x\d+\s+([\w-]+)\s+' # 정책 이름 (None, junos-dns-udp, icmp 등)
    r'[\d\.a-fA-F:]+/\d+->[\d\.a-fA-F:]+/\d+'  # 중간 IP 부분 (무시)
    r'.*?\s+(\d+)\s+(\d+)\s+([\w-]+)\s+([\w-]+)' # 프로토콜 번호, 세션 ID, 소스 존, 대상 존
)

# 수정된 정규식 패턴
#IMPROVED_PATTERN = re.compile(
#    r'.*RT_FLOW: RT_FLOW_SESSION_(?:CREATE|CLOSE):' # 세션 시작/종료
#    r'(?:\s+session\s+closed\s+(?:[\w\s]+\s+)?(?:Timeout|received):)?\s*' # 세션 종료 원인 (선택적)
#    r'([\d\.a-fA-F:]+)/(\d+)->([\d\.a-fA-F:]+)/(\d+)' # 첫 번째 IP 주소/포트 쌍
#    r'\s+0x\d+\s+([\w-]+)\s+' # 정책 이름 (None, junos-dns-udp, icmp 등)
#    r'[\d\.a-fA-F:]+/\d+->[\d\.a-fA-F:]+/\d+.*?' # 중간 IP 부분 (무시)
#    r'(\d+)\s+([A-Z0-9_]+)\s+([\w-]+)\s+([\w-]+)' # 프로토콜 번호, 상태, 소스 존, 대상 존
#)

IMPROVED_PATTERN = re.compile(
    r'.*RT_FLOW: RT_FLOW_SESSION_(?:CREATE|CLOSE):' # 세션 시작/종료
#   r'(?:\s+session\s+closed\s+([\w\s]+):)?\s*' # 세션 종료 원인 (선택적)
    r'(?:\s+session\s+([a-zA-Z\s]+)):?\s*' # 세션 종료 원인 (선택적)
    r'([\d\.a-fA-F:]+)/(\d+)->([\d\.a-fA-F:]+)/(\d+)' # 첫 번째 IP 주소/포트 쌍
    r'\s+0x\d+\s+([\w-]+)\s+' # 서비스 이름 (icmp, icmpv6 등)
    r'[\d\.a-fA-F:]+/\d+->[\d\.a-fA-F:]+/\d+\s+' # 중간 부분 (고정 패턴)
    r'.*?A\s+(\d+)\s+([\w-]+)\s+([\w-]+)\s+([\w-]+)' # 프로토콜 ID, 정책 이름, 소스 존, 대상 존
)


# 더 유연한 파싱 방식
def flexible_parse(line):
    """
    위치에 덜 의존적인 방식으로 로그를 파싱합니다.
    """
    if "RT_FLOW_SESSION" not in line:
        return None
        
    try:
        # 기본 정보 초기화
        log_info = {
            'source_ip': None,
            'destination_ip': None,
            'source_port': None,
            'destination_port': None,
            'protocol': 'unknown',
            'source_zone': 'unknown',
            'destination_zone': 'unknown',
            'policy_name': 'unknown',
            'session_type': 'CREATE' if 'SESSION_CREATE' in line else 'CLOSE'
        }
        
        # IP/포트 패턴 추출
        ip_pattern = re.search(r'([\d\.a-fA-F:]+)/(\d+)->([\d\.a-fA-F:]+)/(\d+)', line)
        if ip_pattern:
            log_info['source_ip'] = ip_pattern.group(1)
            log_info['source_port'] = int(ip_pattern.group(2))
            log_info['destination_ip'] = ip_pattern.group(3)
            log_info['destination_port'] = int(ip_pattern.group(4))
        
        # 영역 정보 추출 - 일반적으로 마지막에 위치한 trust/untrust 단어
        zones = re.findall(r'\b(trust|untrust|[\w-]+zone)\b', line)
        if len(zones) >= 2:
            # 로그 후반부에서 영역 정보를 찾아보자
            parts = line.split()
            for i in range(len(parts) - 2, 0, -1):
                if parts[i] in ('trust', 'untrust') and i+1 < len(parts) and parts[i+1] in ('trust', 'untrust'):
                    log_info['source_zone'] = parts[i]
                    log_info['destination_zone'] = parts[i+1]
                    break
        
        # 정책 이름 추출 - 일반적으로 0x0 다음에 위치
        policy_match = re.search(r'0x\d+\s+([\w-]+)', line)
        if policy_match:
            log_info['policy_name'] = policy_match.group(1)
            
        # 프로토콜 정보 추출
        if 'icmp' in line.lower():
            log_info['protocol'] = 'icmp'
        elif 'tcp' in line.lower():
            log_info['protocol'] = 'tcp'
        elif 'udp' in line.lower():
            log_info['protocol'] = 'udp'
            
        # 세션 종료 원인 추출 (CLOSE 세션의 경우)
        if log_info['session_type'] == 'CLOSE':
            reason_match = re.search(r'session\s+closed\s+(?:response\s+received:)?\s*([\w\s]+):', line)
            if reason_match:
                log_info['close_reason'] = reason_match.group(1).strip()
        
        return log_info
        
    except Exception as e:
        print(f"Error parsing log line: {e}")
        return None

def test_patterns():
    # 테스트할 로그 라인
    test_logs = [
        # 다양한 로그 형식을 여기에 추가할 수 있습니다
    "<14>Jun 17 16:49:31 TA-FW_SRX1500 RT_FLOW: RT_FLOW_SESSION_CREATE: session created 10.1.37.45/41013->180.225.82.115/3306 0x0 None 10.1.37.45/41013->180.225.82.115/3306 0x0 N/A N/A N/A N/A 6 1 V40 V30 1047299 N/A(N/A) reth2.0 UNKNOWN UNKNOWN UNKNOWN N/A N/A -1 N/A N/A N/A Off root",
    #    "<14>Jun 16 17:01:02 TA-FW_SRX1500 RT_FLOW: RT_FLOW_SESSION_CLOSE: session closed TCP FIN: 122.35.0.54/59287->10.1.2.200/3306 0x0 None 122.35.0.54/59287->10.1.2.200/3306 0x0 N/A N/A N/A N/A 6 1 V40 Untrust 1714411 10(550) 9(709) 1 UNKNOWN UNKNOWN N/A(N/A) reth2.0 UNKNOWN N/A N/A -1 N/A NA 0 0.0.0.0/0->0.0.0.0/0 NA NA N/A N/A Off root"
    ]
    
    print("=" * 80)
    print("테스트 시작: 로그 파싱 패턴 비교")
    print("=" * 80)
    
    for i, log in enumerate(test_logs):
        print(f"\n로그 #{i+1}:")
        print(f"{log[:160]}..." if len(log) > 160 else log)
        print("-" * 80)
        
        # 기존 패턴 테스트
        original_match = ORIGINAL_PATTERN.match(log)
        print("1. 기존 패턴 결과:")
        if original_match:
            groups = original_match.groups()
            print(f"  매치됨! {len(groups)}개 그룹 발견")
            print(f"  - 종료 원인: {groups[0]}")
            print(f"  - 소스 IP/포트: {groups[1]}/{groups[2]}")
            print(f"  - 대상 IP/포트: {groups[3]}/{groups[4]}")
            print(f"  - 서비스 이름: {groups[5]}")
            print(f"  - 프로토콜: {groups[6]}")
            print(f"  - 정책 ID: {groups[7]}")
            print(f"  - 소스 존: {groups[8]}")
            print(f"  - 대상 존: {groups[9]}")
        else:
            print("  매치되지 않음!")
        
        print("\n2. 개선된 패턴 결과:")
        # 개선된 패턴 테스트
        improved_match = IMPROVED_PATTERN.match(log)
        if improved_match:
            groups = improved_match.groups()
            print(f"  매치됨! {len(groups)}개 그룹 발견")
            print(f"  - 종료 원인: {groups[0]}")
            print(f"  - 소스 IP/포트: {groups[1]}/{groups[2]}")
            print(f"  - 대상 IP/포트: {groups[3]}/{groups[4]}")
            print(f"  - 서비스 이름: {groups[5]}")
            print(f"  - 프로토콜: {groups[6]}")
            print(f"  - 정책 ID: {groups[7]}")
            print(f"  - 소스 존: {groups[8]}")
            print(f"  - 대상 존: {groups[9]}")
        else:
            print("  매치되지 않음!")
        
        print("\n3. 유연한 파싱 결과:")
        # 유연한 파싱 방식 테스트
        flexible_result = flexible_parse(log)
        if flexible_result:
            print(f"  파싱 성공!")
            for key, value in flexible_result.items():
                print(f"  - {key}: {value}")
        else:
            print("  파싱 실패!")
    
    print("\n" + "=" * 80)
    print("테스트 완료")
    print("=" * 80)

def parse_log_file(file_path):
    """
    로그 파일을 파싱하여 기존 패턴과 개선된 패턴의 성공률을 비교합니다.
    """
    original_success = 0
    improved_success = 0
    flexible_success = 0
    total_lines = 0
    
    try:
        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                if 'RT_FLOW_SESSION' in line:
                    total_lines += 1
                    
                    # 기존 패턴 테스트
                    if ORIGINAL_PATTERN.match(line):
                        original_success += 1
                    else:
                        print(f"{line}")
                    
                    # 개선된 패턴 테스트
                    if IMPROVED_PATTERN.match(line):
                        improved_success += 1
                    
                    # 유연한 파싱 테스트
                    if flexible_parse(line):
                        flexible_success += 1
        
        # 결과 출력
        if total_lines > 0:
            print(f"\n로그 파일 '{file_path}' 파싱 결과:")
            print(f"총 로그 라인 수: {total_lines}")
            print(f"기존 패턴 성공률: {original_success}/{total_lines} ({original_success/total_lines*100:.2f}%)")
            print(f"개선된 패턴 성공률: {improved_success}/{total_lines} ({improved_success/total_lines*100:.2f}%)")
            print(f"유연한 파싱 성공률: {flexible_success}/{total_lines} ({flexible_success/total_lines*100:.2f}%)")
        else:
            print(f"\n로그 파일 '{file_path}'에서 RT_FLOW_SESSION 로그를 찾을 수 없습니다.")
    
    except Exception as e:
        print(f"파일 파싱 중 오류 발생: {e}")

def interactive_test():
    """
    사용자가 직접 로그 라인을 입력하여 테스트하는 모드
    """
    print("\n" + "=" * 80)
    print("인터랙티브 테스트 모드")
    print("로그 라인을 직접 입력하여 파싱을 테스트합니다. (종료하려면 빈 줄 입력)")
    print("=" * 80)
    
    while True:
        print("\n로그 라인 입력: ", end="")
        log_line = input().strip()
        
        if not log_line:
            break
        
        # 원본 패턴 테스트
        original_match = ORIGINAL_PATTERN.match(log_line)
        print("\n1. 기존 패턴 결과:")
        if original_match:
            print("  매치됨!")
            for i, group in enumerate(original_match.groups()):
                print(f"  - 그룹 {i+1}: {group}")
        else:
            print("  매치되지 않음!")
        
        # 개선된 패턴 테스트
        improved_match = IMPROVED_PATTERN.match(log_line)
        print("\n2. 개선된 패턴 결과:")
        if improved_match:
            print("  매치됨!")
            for i, group in enumerate(improved_match.groups()):
                print(f"  - 그룹 {i+1}: {group}")
        else:
            print("  매치되지 않음!")
        
        # 유연한 파싱 방식 테스트
        flexible_result = flexible_parse(log_line)
        print("\n3. 유연한 파싱 결과:")
        if flexible_result:
            print("  파싱 성공!")
            for key, value in flexible_result.items():
                print(f"  - {key}: {value}")
        else:
            print("  파싱 실패!")

def main():
    """
    메인 함수 - 다양한 테스트 모드 지원
    """
    if len(sys.argv) > 1:
        if sys.argv[1] == "--help" or sys.argv[1] == "-h":
            print("사용법:")
            print("  python log_parser_test.py              # 기본 테스트 실행")
            print("  python log_parser_test.py --file FILE  # 파일 파싱 테스트")
            print("  python log_parser_test.py --interactive # 인터랙티브 테스트")
            return
        
        if sys.argv[1] == "--file" and len(sys.argv) > 2:
            # 파일 파싱 모드
            parse_log_file(sys.argv[2])
            return
        
        if sys.argv[1] == "--interactive":
            # 인터랙티브 테스트 모드
            interactive_test()
            return
    
    # 기본 테스트 실행
    test_patterns()

if __name__ == "__main__":
    main()
