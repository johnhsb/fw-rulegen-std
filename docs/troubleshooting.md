# 문제 해결 가이드

이 문서는 방화벽 정책 추천 시스템 사용 중 발생할 수 있는 일반적인 문제와 해결 방법을 제공합니다.

## 목차

1. [설치 관련 문제](#설치-관련-문제)
2. [로그인 및 인증 문제](#로그인-및-인증-문제)
3. [로그 파일 업로드 문제](#로그-파일-업로드-문제)
4. [Syslog 서버 문제](#syslog-서버-문제)
5. [분석 실행 문제](#분석-실행-문제)
6. [성능 문제](#성능-문제)
7. [시각화 문제](#시각화-문제)
8. [네트워크 문제](#네트워크-문제)

## 설치 관련 문제

### 문제: pip 패키지 설치 실패

**증상**: `pip install -r requirements.txt` 실행 시 오류 발생

**해결 방법**:

1. pip 업그레이드:
```bash
python -m pip install --upgrade pip
```

2. 특정 패키지 설치 실패 시:
```bash
# scikit-learn 설치 오류
pip install --upgrade scikit-learn==1.0.2

# pandas 설치 오류
pip install --upgrade pandas==1.5.3
```

3. 시스템 의존성 설치:
```bash
# Ubuntu/Debian
sudo apt-get install python3-dev build-essential

# CentOS/RHEL
sudo yum install python3-devel gcc
```

### 문제: 디렉토리 권한 오류

**증상**: "Permission denied" 오류 발생

**해결 방법**:

```bash
# 필요한 디렉토리 생성 및 권한 설정
sudo mkdir -p logs static/output
sudo chown -R $USER:$USER logs static/output
chmod 755 logs static/output
```

## 로그인 및 인증 문제

### 문제: 기본 계정으로 로그인 불가

**증상**: admin/admin으로 로그인 실패

**해결 방법**:

1. users.json 파일 확인:
```bash
cat config/users.json
```

2. 파일이 없거나 손상된 경우 재생성:
```bash
cat > config/users.json << EOF
{
  "users": [
    {
      "username": "admin",
      "password": "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    }
  ]
}
EOF
```

3. 비밀번호 해시 직접 생성:
```python
import hashlib
password = "admin"
hashed = hashlib.sha256(password.encode()).hexdigest()
print(f"Hashed password: {hashed}")
```

### 문제: 세션 만료

**증상**: 자동 로그아웃 발생

**해결 방법**:

1. 세션 타임아웃 설정 확인 (config/config.py):
```python
PERMANENT_SESSION_LIFETIME = timedelta(hours=1)  # 1시간으로 조정
```

2. 세션 파일 권한 확인:
```bash
chmod -R 755 flask_sessions/
```

## 로그 파일 업로드 문제

### 문제: "파일 크기 초과" 오류

**증상**: 200MB 이상 파일 업로드 시 오류

**해결 방법**:

1. 파일 크기 제한 변경 (config/config.py):
```python
MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500MB로 증가
```

2. 서버 재시작:
```bash
sudo systemctl restart firewall-policy-recommender
```

### 문제: 지원되지 않는 로그 형식

**증상**: "유효한 로그 데이터를 찾을 수 없습니다" 오류

**해결 방법**:

1. 로그 형식 확인:
```bash
# 정상적인 주니퍼 로그 예시
grep "RT_FLOW" your_log_file.log | head -5
```

2. 로그 파서 regex 패턴 확인 (modules/log_parser.py):
```python
JUNIPER_SESSION_PATTERN = re.compile(
    r'.*RT_FLOW: RT_FLOW_SESSION_(?:CREATE|CLOSE):'
    # ... 패턴 확인
)
```

## Syslog 서버 문제

### 문제: Syslog 서버 시작 실패

**증상**: "Address already in use" 오류

**해결 방법**:

1. 포트 사용 확인:
```bash
sudo netstat -tulpn | grep :514
```

2. 기존 프로세스 종료:
```bash
sudo kill -9 $(sudo lsof -t -i:514)
```

3. 다른 포트 사용:
```python
# Syslog 설정에서 포트 변경
syslog_config = {
    'port': 5514  # 514 대신 5514 사용
}
```

### 문제: 방화벽에서 로그 수신 안됨

**증상**: Syslog 서버는 실행 중이나 로그가 수신되지 않음

**해결 방법**:

1. 방화벽 규칙 확인:
```bash
# UDP 514 포트 허용
sudo ufw allow 514/udp
```

2. tcpdump로 패킷 확인:
```bash
sudo tcpdump -i any -n port 514
```

3. 방화벽 설정 확인:
```
# 주니퍼 방화벽
show configuration system syslog
```

## 분석 실행 문제

### 문제: 메모리 부족 오류

**증상**: "MemoryError" 또는 시스템 멈춤

**해결 방법**:

1. 분석 파라미터 조정:
```python
# max_data_points 감소
params = {
    'max_data_points': 5000  # 10000에서 5000으로 감소
}
```

2. 스왑 메모리 추가:
```bash
sudo dd if=/dev/zero of=/swapfile bs=1G count=4
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

3. 데이터 필터링 적용:
```python
# 날짜 범위 제한
filters = {
    'start_date': '2024-01-01',
    'end_date': '2024-01-31'
}
```

### 문제: 클러스터링 결과 없음

**증상**: "클러스터: 0" 메시지

**해결 방법**:

1. DBSCAN 파라미터 조정:
```python
# eps 값 증가 (클러스터링 기준 완화)
params = {
    'eps': 1.0,  # 0.5에서 1.0으로 증가
    'min_samples': 2  # 최소값 유지
}
```

2. 데이터 확인:
```python
# 로그 데이터 분포 확인
print(f"고유 IP 쌍: {len(df[['source_ip', 'destination_ip']].drop_duplicates())}")
print(f"전체 레코드: {len(df)}")
```

## 성능 문제

### 문제: 분석 속도 느림

**증상**: 분석이 오래 걸림 (10분 이상)

**해결 방법**:

1. 데이터 양 제한:
```python
# 최소 발생 횟수 증가
params = {
    'min_occurrences': 5  # 1에서 5로 증가
}
```

2. 인덱스 최적화:
```python
# DataFrame 인덱스 설정
df.set_index(['source_ip', 'destination_ip'], inplace=True)
```

3. 메모리 캐싱 활용:
```python
# functools.lru_cache 사용
from functools import lru_cache

@lru_cache(maxsize=1000)
def ip_to_int(ip):
    # IP 변환 로직
```

### 문제: 웹 인터페이스 응답 없음

**증상**: 페이지 로딩이 멈춤

**해결 방법**:

1. 워커 프로세스 확인:
```bash
ps aux | grep app.py
```

2. 로그 확인:
```bash
tail -f firewall_recommender.log
```

3. 서버 재시작:
```bash
sudo systemctl restart firewall-policy-recommender
```

## 시각화 문제

### 문제: 3D 시각화가 표시되지 않음

**증상**: 빈 화면 또는 로딩 중 메시지

**해결 방법**:

1. 브라우저 콘솔 확인:
- F12 키로 개발자 도구 열기
- Console 탭에서 에러 메시지 확인

2. WebGL 지원 확인:
```javascript
// 브라우저 콘솔에서 실행
console.log(!!window.WebGLRenderingContext);
```

3. 브라우저 캐시 삭제:
- Ctrl+Shift+Del (Windows/Linux)
- Cmd+Shift+Del (macOS)

### 문제: Sankey 다이어그램 렌더링 오류

**증상**: "Invalid trace type: sankey" 오류

**해결 방법**:

1. Plotly 버전 확인:
```python
import plotly
print(plotly.__version__)  # 5.0.0 이상 필요
```

2. 의존성 재설치:
```bash
pip install --upgrade plotly
```

## 네트워크 문제

### 문제: SSL 인증서 오류

**증상**: "ERR_CERT_AUTHORITY_INVALID" 브라우저 오류

**해결 방법**:

1. 자체 서명 인증서 경고 무시:
- Chrome: "고급" → "안전하지 않은 사이트로 이동"
- Firefox: "고급" → "위험을 감수하고 계속"

2. 유효한 인증서 설치:
```bash
# Let's Encrypt 인증서 발급
sudo certbot certonly --standalone -d your-domain.com
```

### 문제: 방화벽 차단

**증상**: 연결 시간 초과

**해결 방법**:

1. 로컬 방화벽 규칙 확인:
```bash
# Ubuntu/Debian
sudo ufw status
sudo ufw allow 14000/tcp

# CentOS/RHEL  
sudo firewall-cmd --list-all
sudo firewall-cmd --permanent --add-port=14000/tcp
```

2. 클라우드 보안 그룹 확인:
- AWS: Security Groups에서 인바운드 규칙 확인
- Azure: Network Security Groups 설정 확인

## 로그 수집 및 디버깅

### 애플리케이션 로그 확인

```bash
# 실시간 로그 모니터링
tail -f firewall_recommender.log

# 오류 메시지 검색
grep -i error firewall_recommender.log

# 특정 모듈 로그 필터링
grep "traffic_analyzer" firewall_recommender.log
```

### 디버그 모드 실행

```python
# app.py 수정
if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=14000)
```

### 시스템 리소스 모니터링

```bash
# CPU 및 메모리 사용량
htop

# 디스크 사용량
df -h

# 네트워크 연결 상태
netstat -tulpn
```

## 추가 지원

위 해결 방법으로도 문제가 해결되지 않는 경우:

1. GitHub 이슈 등록
2. 로그 파일 첨부 (민감 정보 제거)
3. 시스템 환경 정보 제공:
   - OS 및 버전
   - Python 버전
   - 메모리 용량
   - 로그 파일 크기

## 자주 묻는 질문 (FAQ)

**Q: 분석이 완료되었지만 정책이 생성되지 않습니다.**

A: 트래픽 패턴이 충분하지 않을 수 있습니다. `min_occurrences` 값을 낮추거나 데이터 범위를 확대해보세요.

**Q: IPv6 트래픽이 분석되지 않습니다.**

A: 로그에 IPv6 트래픽이 포함되어 있는지 확인하세요:
```bash
grep -E "([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}" your_log_file.log
```

**Q: 정책 이름이 너무 깁니다.**

A: `policy_generator.py`에서 정책 이름 생성 로직을 수정할 수 있습니다:
```python
def generate_descriptive_policy_name(self, ...):
    # 더 짧은 이름 생성 로직
    return f"P{cluster_id}-{port_ranges[0]}"
```
