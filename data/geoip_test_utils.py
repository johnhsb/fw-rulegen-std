#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GeoIP 기능 테스트 및 디버깅 유틸리티
----------------------------------
GeoIP 데이터베이스 연결 상태 확인 및 기능 테스트를 위한 도구
"""

import os
import logging
import pandas as pd
from modules.traffic_analyzer import GeoIPAnalyzer, TrafficAnalyzer

logger = logging.getLogger(__name__)

def test_geoip_databases(data_dir='.'):
    """
    GeoIP 데이터베이스 파일 존재 여부 및 연결 상태 테스트
    
    Args:
        data_dir (str): GeoIP 데이터베이스 디렉토리
        
    Returns:
        dict: 테스트 결과
    """
    print("=== GeoIP 데이터베이스 테스트 ===")
    
    data_dir = os.path.expanduser(data_dir)
    results = {
        'data_dir_exists': False,
        'country_db_exists': False,
        'asn_db_exists': False,
        'country_db_readable': False,
        'asn_db_readable': False,
        'test_queries': []
    }
    
    # 디렉토리 존재 확인
    if os.path.exists(data_dir):
        results['data_dir_exists'] = True
        print(f"✓ 데이터 디렉토리 존재: {data_dir}")
    else:
        print(f"✗ 데이터 디렉토리 없음: {data_dir}")
        return results
    
    # 데이터베이스 파일 존재 확인
    country_db_path = os.path.join(data_dir, 'GeoLite2-Country.mmdb')
    asn_db_path = os.path.join(data_dir, 'GeoLite2-ASN.mmdb')
    
    if os.path.exists(country_db_path):
        results['country_db_exists'] = True
        file_size = os.path.getsize(country_db_path) / (1024*1024)
        print(f"✓ 국가 데이터베이스 존재: {country_db_path} ({file_size:.1f}MB)")
    else:
        print(f"✗ 국가 데이터베이스 없음: {country_db_path}")
    
    if os.path.exists(asn_db_path):
        results['asn_db_exists'] = True
        file_size = os.path.getsize(asn_db_path) / (1024*1024)
        print(f"✓ ASN 데이터베이스 존재: {asn_db_path} ({file_size:.1f}MB)")
    else:
        print(f"✗ ASN 데이터베이스 없음: {asn_db_path}")
    
    # GeoIP 분석기 테스트
    try:
        analyzer = GeoIPAnalyzer(data_dir)
        
        # 테스트 IP 주소들
        test_ips = [
            '8.8.8.8',          # Google DNS (미국)
            '1.1.1.1',          # Cloudflare DNS (미국)
            '208.67.222.222',   # OpenDNS (미국)
            '168.126.63.1',     # KT DNS (한국)
            '2001:4860:4860::8888',  # Google DNS IPv6
            '192.168.1.1',      # 사설 IP
            '10.0.0.1'          # 사설 IP
        ]
        
        print("\n=== IP 주소 조회 테스트 ===")
        for ip in test_ips:
            try:
                country_info = analyzer.get_country_info(ip)
                asn_info = analyzer.get_asn_info(ip)
                
                test_result = {
                    'ip': ip,
                    'country': country_info,
                    'asn': asn_info,
                    'success': True
                }
                results['test_queries'].append(test_result)
                
                print(f"IP: {ip}")
                print(f"  국가: {country_info['country_name']} ({country_info['country_code']})")
                print(f"  ASN: AS{asn_info['asn']} - {asn_info['org']}")
                print()
                
                if analyzer.country_db:
                    results['country_db_readable'] = True
                if analyzer.asn_db:
                    results['asn_db_readable'] = True
                    
            except Exception as e:
                test_result = {
                    'ip': ip,
                    'error': str(e),
                    'success': False
                }
                results['test_queries'].append(test_result)
                print(f"IP: {ip} - 오류: {e}")
        
        analyzer.close()
        
    except Exception as e:
        print(f"GeoIP 분석기 초기화 오류: {e}")
    
    # 결과 요약
    print("\n=== 테스트 결과 요약 ===")
    print(f"데이터 디렉토리: {'✓' if results['data_dir_exists'] else '✗'}")
    print(f"국가 DB 파일: {'✓' if results['country_db_exists'] else '✗'}")
    print(f"ASN DB 파일: {'✓' if results['asn_db_exists'] else '✗'}")
    print(f"국가 DB 읽기: {'✓' if results['country_db_readable'] else '✗'}")
    print(f"ASN DB 읽기: {'✓' if results['asn_db_readable'] else '✗'}")
    
    successful_queries = len([q for q in results['test_queries'] if q.get('success', False)])
    print(f"성공한 쿼리: {successful_queries}/{len(results['test_queries'])}")
    
    return results

def create_sample_traffic_data():
    """
    테스트용 샘플 트래픽 데이터 생성
    
    Returns:
        pd.DataFrame: 샘플 트래픽 데이터
    """
    print("=== 샘플 트래픽 데이터 생성 ===")
    
    sample_data = [
        # 국내 트래픽
        {'source_ip': '192.168.1.100', 'destination_ip': '168.126.63.1', 'source_port': 12345, 'destination_port': 53, 'protocol': 'udp', 'source_zone': 'trust', 'destination_zone': 'untrust'},
        {'source_ip': '192.168.1.101', 'destination_ip': '168.126.63.1', 'source_port': 12346, 'destination_port': 53, 'protocol': 'udp', 'source_zone': 'trust', 'destination_zone': 'untrust'},
        
        # 국제 트래픽 (미국)
        {'source_ip': '192.168.1.100', 'destination_ip': '8.8.8.8', 'source_port': 12347, 'destination_port': 53, 'protocol': 'udp', 'source_zone': 'trust', 'destination_zone': 'untrust'},
        {'source_ip': '192.168.1.101', 'destination_ip': '1.1.1.1', 'source_port': 12348, 'destination_port': 53, 'protocol': 'udp', 'source_zone': 'trust', 'destination_zone': 'untrust'},
        
        # 웹 트래픽
        {'source_ip': '192.168.1.100', 'destination_ip': '142.250.196.142', 'source_port': 12349, 'destination_port': 443, 'protocol': 'tcp', 'source_zone': 'trust', 'destination_zone': 'untrust'},
        {'source_ip': '192.168.1.101', 'destination_ip': '142.250.196.142', 'source_port': 12350, 'destination_port': 443, 'protocol': 'tcp', 'source_zone': 'trust', 'destination_zone': 'untrust'},
        
        # IPv6 트래픽
        {'source_ip': '2001:db8::1', 'destination_ip': '2001:4860:4860::8888', 'source_port': 12351, 'destination_port': 53, 'protocol': 'udp', 'source_zone': 'trust', 'destination_zone': 'untrust'},
        
        # ICMP 트래픽
        {'source_ip': '192.168.1.100', 'destination_ip': '8.8.8.8', 'source_port': 0, 'destination_port': 0, 'protocol': 'icmp', 'source_zone': 'trust', 'destination_zone': 'untrust'},
    ]
    
    # 데이터 중복 생성 (빈도 시뮬레이션)
    expanded_data = []
    for _ in range(100):  # 각 패턴을 100번 반복
        for item in sample_data:
            expanded_data.append(item.copy())
    
    df = pd.DataFrame(expanded_data)
    
    # is_ipv6 컬럼 추가
    df['is_ipv6'] = df['source_ip'].apply(lambda x: ':' in str(x))
    
    print(f"샘플 데이터 생성 완료: {len(df)} 레코드")
    print(f"IPv4 레코드: {len(df[~df['is_ipv6']])}개")
    print(f"IPv6 레코드: {len(df[df['is_ipv6']])}개")
    
    return df

def test_geoip_analysis(sample_data=None):
    """
    GeoIP 기반 트래픽 분석 테스트
    
    Args:
        sample_data (pd.DataFrame): 테스트용 데이터 (None이면 자동 생성)
        
    Returns:
        dict: 테스트 결과
    """
    print("\n=== GeoIP 트래픽 분석 테스트 ===")
    
    if sample_data is None:
        sample_data = create_sample_traffic_data()
    
    try:
        # 트래픽 분석기 초기화
        analyzer = TrafficAnalyzer(
            sample_data, 
            min_occurrences=1,
            eps=0.5,
            min_samples=2,
            max_data_points=1000
        )
        
        print("트래픽 분석기 초기화 완료")
        
        # 클러스터링 수행
        clustered_df = analyzer.cluster_traffic_patterns()
        print(f"클러스터링 완료: {len(clustered_df)} 레코드")
        
        # 정책 추천 생성
        policies = analyzer.generate_policy_recommendations()
        print(f"정책 추천 생성 완료: {len(policies)}개 정책")
        
        # 국가별 시각화 테스트
        print("국가별 Sankey 다이어그램 생성 테스트...")
        country_viz = analyzer.visualize_traffic_sankey_by_country('test_country_sankey')
        
        # ASN별 시각화 테스트
        print("ASN별 Sankey 다이어그램 생성 테스트...")
        asn_viz = analyzer.visualize_traffic_sankey_by_asn('test_asn_sankey')
        
        test_results = {
            'success': True,
            'clustered_records': len(clustered_df),
            'policies_count': len(policies),
            'country_viz_files': country_viz,
            'asn_viz_files': asn_viz,
            'policies': policies[:3] if policies else []  # 처음 3개 정책만 저장
        }
        
        print("✓ GeoIP 트래픽 분석 테스트 성공")
        return test_results
        
    except Exception as e:
        print(f"✗ GeoIP 트래픽 분석 테스트 실패: {e}")
        return {'success': False, 'error': str(e)}

def check_system_requirements():
    """
    시스템 요구사항 확인
    
    Returns:
        dict: 요구사항 체크 결과
    """
    print("\n=== 시스템 요구사항 확인 ===")
    
    requirements = {
        'python_version': False,
        'required_packages': {},
        'memory': False,
        'disk_space': False
    }
    
    # Python 버전 확인
    import sys
    python_version = sys.version_info
    if python_version >= (3, 8):
        requirements['python_version'] = True
        print(f"✓ Python 버전: {python_version.major}.{python_version.minor}.{python_version.micro}")
    else:
        print(f"✗ Python 버전 부족: {python_version.major}.{python_version.minor}.{python_version.micro} (최소 3.8 필요)")
    
    # 필수 패키지 확인
    required_packages = {
        'pandas': '2.0.0',
        'numpy': '1.24.0',
        'scikit-learn': '1.3.0',
        'plotly': '5.15.0',
        'geoip2': '4.6.0',
        'flask': '2.3.0'
    }
    
    for package, min_version in required_packages.items():
        try:
            module = __import__(package)
            if hasattr(module, '__version__'):
                version = module.__version__
                requirements['required_packages'][package] = {'installed': True, 'version': version}
                print(f"✓ {package}: {version}")
            else:
                requirements['required_packages'][package] = {'installed': True, 'version': 'unknown'}
                print(f"? {package}: 설치됨 (버전 불명)")
        except ImportError:
            requirements['required_packages'][package] = {'installed': False}
            print(f"✗ {package}: 설치되지 않음")
    
    # 메모리 확인
    try:
        import psutil
        memory = psutil.virtual_memory()
        memory_gb = memory.total / (1024**3)
        if memory_gb >= 4:
            requirements['memory'] = True
            print(f"✓ 메모리: {memory_gb:.1f}GB")
        else:
            print(f"? 메모리: {memory_gb:.1f}GB (권장: 4GB 이상)")
    except ImportError:
        print("? 메모리 정보를 확인할 수 없음 (psutil 필요)")
    
    # 디스크 공간 확인
    try:
        import shutil
        disk_usage = shutil.disk_usage('.')
        free_gb = disk_usage.free / (1024**3)
        if free_gb >= 1:
            requirements['disk_space'] = True
            print(f"✓ 디스크 여유공간: {free_gb:.1f}GB")
        else:
            print(f"? 디스크 여유공간: {free_gb:.1f}GB (권장: 1GB 이상)")
    except Exception:
        print("? 디스크 공간 정보를 확인할 수 없음")
    
    return requirements

def run_complete_test():
    """
    전체 테스트 실행
    
    Returns:
        dict: 전체 테스트 결과
    """
    print("=" * 60)
    print("GeoIP 기능 완전 테스트 시작")
    print("=" * 60)
    
    results = {}
    
    # 1. 시스템 요구사항 확인
    results['system'] = check_system_requirements()
    
    # 2. GeoIP 데이터베이스 테스트
    results['geoip_db'] = test_geoip_databases()
    
    # 3. GeoIP 분석 테스트
    if results['geoip_db']['country_db_readable'] or results['geoip_db']['asn_db_readable']:
        results['geoip_analysis'] = test_geoip_analysis()
    else:
        print("\n✗ GeoIP 데이터베이스 읽기 불가로 분석 테스트 건너뜀")
        results['geoip_analysis'] = {'success': False, 'error': 'GeoIP databases not readable'}
    
    # 4. 결과 요약
    print("\n" + "=" * 60)
    print("테스트 결과 요약")
    print("=" * 60)
    
    # 시스템 요구사항 요약
    system_ok = all([
        results['system']['python_version'],
        all(pkg['installed'] for pkg in results['system']['required_packages'].values())
    ])
    print(f"시스템 요구사항: {'✓' if system_ok else '✗'}")
    
    # GeoIP 데이터베이스 요약
    geoip_ok = results['geoip_db']['country_db_readable'] and results['geoip_db']['asn_db_readable']
    print(f"GeoIP 데이터베이스: {'✓' if geoip_ok else '✗'}")
    
    # GeoIP 분석 요약
    analysis_ok = results['geoip_analysis']['success']
    print(f"GeoIP 분석 기능: {'✓' if analysis_ok else '✗'}")
    
    # 전체 결과
    all_ok = system_ok and geoip_ok and analysis_ok
    print(f"\n전체 테스트: {'✓ 성공' if all_ok else '✗ 실패'}")
    
    if not all_ok:
        print("\n문제 해결 방법:")
        if not system_ok:
            print("- pip install -r requirements.txt 명령으로 필수 패키지 설치")
        if not geoip_ok:
            print("- ~/data/ 디렉토리에 GeoLite2-Country.mmdb와 GeoLite2-ASN.mmdb 파일 확인")
            print("- MaxMind에서 GeoLite2 데이터베이스 다운로드")
    
    results['overall_success'] = all_ok
    return results

if __name__ == "__main__":
    # 직접 실행 시 전체 테스트 수행
    run_complete_test()
