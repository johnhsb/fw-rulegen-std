# API 레퍼런스

## 개요

방화벽 정책 추천 시스템의 모든 API 엔드포인트에 대한 상세 문서입니다. 모든 API 호출은 인증이 필요하며, 세션 기반으로 동작합니다.

## 인증

모든 API 엔드포인트는 로그인 세션이 필요합니다. 로그인하지 않은 상태에서 API를 호출하면 로그인 페이지로 리다이렉트됩니다.

### 로그인

```http
POST /login
Content-Type: application/x-www-form-urlencoded

username=admin&password=admin
```

**응답**:
- 성공: 302 Redirect to /
- 실패: 200 OK with error message

### 로그아웃

```http
GET /logout
```

**응답**: 302 Redirect to /login

## 로그 관리 API

### 로그 파일 업로드

```http
POST /upload
Content-Type: multipart/form-data

logfile=@firewall.log
```

**파라미터**:
- `logfile`: 업로드할 로그 파일 (여러 파일 가능)

**응답**:
```json
{
  "success": true,
  "files": [
    "/tmp/fw_rulegen_uploads/firewall.log"
  ]
}
```

**에러 응답**:
```json
{
  "error": "파일이 선택되지 않았습니다"
}
```

## 분석 API

### 로그 분석 실행

```http
POST /api/analyze
Content-Type: application/x-www-form-urlencoded

min_occurrences=1&eps=0.5&min_samples=2&max_data_points=10000&
device_name_filter=fw-01&device_name_filter_type=include&
source_ip_filter=192.168.1.0/24&source_ip_filter_type=include&
destination_ip_filter=8.8.8.8&destination_ip_filter_type=include&
port_filter=80,443&port_filter_type=include&
protocol_filter=tcp&protocol_filter_type=include&
source_zone_filter=trust&source_zone_filter_type=include&
destination_zone_filter=untrust&destination_zone_filter_type=include&
start_date=2024-01-01&end_date=2024-12-31&
exclude_noise=1
```

**파라미터**:

#### 클러스터링 파라미터
- `min_occurrences`: 최소 발생 횟수 (기본값: 1)
- `eps`: DBSCAN epsilon 값 (기본값: 0.5)
- `min_samples`: 최소 샘플 수 (기본값: 2)
- `max_data_points`: 최대 데이터 포인트 (기본값: 10000)

#### 필터 파라미터
- `device_name_filter`: 장비명 필터
- `device_name_filter_type`: include/exclude
- `source_ip_filter`: 출발지 IP 필터
- `source_ip_filter_type`: include/exclude
- `destination_ip_filter`: 목적지 IP 필터
- `destination_ip_filter_type`: include/exclude
- `port_filter`: 포트 필터
- `port_filter_type`: include/exclude
- `protocol_filter`: 프로토콜 필터
- `protocol_filter_type`: include/exclude
- `source_zone_filter`: 출발지 존 필터
- `source_zone_filter_type`: include/exclude
- `destination_zone_filter`: 목적지 존 필터
- `destination_zone_filter_type`: include/exclude
- `start_date`: 시작 날짜 (YYYY-MM-DD)
- `end_date`: 종료 날짜 (YYYY-MM-DD)
- `exclude_noise`: 노이즈 제외 (0/1)

**응답**:
```json
{
  "success": true,
  "policies_count": 15,
  "timestamp": "20240101_120000",
  "visualizations": {
    "sankey": {
      "ipv4": "traffic_sankey_20240101_120000_ipv4.html",
      "ipv6": "traffic_sankey_20240101_120000_ipv6.html"
    },
    "interactive_3d": {
      "ipv4": "traffic_3d_interactive_20240101_120000_ipv4.html",
      "ipv6": "traffic_3d_interactive_20240101_120000_ipv6.html"
    }
  }
}
```

**에러 응답**:
```json
{
  "error": "로그 파일을 먼저 업로드해 주세요"
}
```

### 분석 결과 조회

```http
GET /analyze?timestamp=20240101_120000
```

**파라미터**:
- `timestamp`: 분석 타임스탬프

**응답**: HTML 페이지

## Syslog 서버 API

### Syslog 서버 제어

```http
POST /syslog
Content-Type: application/x-www-form-urlencoded

action=start&host=0.0.0.0&port=514&interval=3600&
device_filter=fw-01&device_filter_type=include
```

**파라미터**:
- `action`: start/stop
- `host`: 수신 주소 (action=start일 때)
- `port`: 수신 포트 (action=start일 때)
- `interval`: 자동 분석 주기(초) (action=start일 때)
- `device_filter`: 장비 필터 (action=start일 때)
- `device_filter_type`: all/include/exclude (action=start일 때)

**응답**:
```json
{
  "success": true
}
```

**에러 응답**:
```json
{
  "error": "Syslog 서버가 이미 실행 중입니다"
}
```

## 시스템 관리 API

### 시스템 설정

```http
POST /settings
Content-Type: application/x-www-form-urlencoded

min_occurrences=1&eps=0.5&min_samples=2&max_data_points=10000&
output_dir=/tmp/output
```

**파라미터**:
- DBSCAN 파라미터들
- `output_dir`: 출력 디렉토리

**응답**:
```json
{
  "success": true
}
```

### 시스템 정보 조회

```http
GET /api/system_info
```

**응답**:
```json
{
  "disk_usage": "45.2%",
  "memory_usage": "3.2GB / 8GB"
}
```

### 데이터 정리

```http
POST /api/cleanup
Content-Type: application/x-www-form-urlencoded

retention_days=30
```

**파라미터**:
- `retention_days`: 보관 일수

**응답**:
```json
{
  "success": true,
  "message": "30일 이전의 5개 파일이 삭제되었습니다."
}
```

### 로그 파일 목록 조회

```http
GET /api/log_files?type=syslog
```

**파라미터**:
- `type`: syslog/upload

**응답**:
```json
{
  "files": [
    {
      "filename": "fw-01_20240101.log",
      "size": 1048576,
      "modified": "2024-01-01T12:00:00"
    }
  ]
}
```

## 정책 관리 API

### 정책 조회

```http
GET /policies?timestamp=20240101_120000
```

**파라미터**:
- `timestamp`: 분석 타임스탬프 (선택사항)

**응답**: HTML 페이지

### 방화벽 설정 조회

```http
GET /config?timestamp=20240101_120000
```

**파라미터**:
- `timestamp`: 분석 타임스탬프 (선택사항)

**응답**: HTML 페이지

## 웹소켓 API (추후 구현)

실시간 로그 모니터링 및 분석 진행상황을 위한 웹소켓 API가 추후 구현될 예정입니다.

### 연결

```javascript
const ws = new WebSocket('wss://localhost:14000/ws');

ws.onopen = function(event) {
  console.log('Connected to WebSocket');
};

ws.onmessage = function(event) {
  const data = JSON.parse(event.data);
  // 메시지 처리
};
```

### 메시지 형식

#### 분석 진행상황
```json
{
  "type": "analysis_progress",
  "progress": 75,
  "message": "클러스터링 진행 중..."
}
```

#### 실시간 로그
```json
{
  "type": "syslog_received",
  "timestamp": "2024-01-01T12:00:00",
  "source": "192.168.1.1",
  "message": "RT_FLOW: RT_FLOW_SESSION_CREATE..."
}
```

## 에러 코드

| 코드 | 설명 |
|------|------|
| 400 | 잘못된 요청 파라미터 |
| 401 | 인증 필요 |
| 404 | 리소스를 찾을 수 없음 |
| 413 | 업로드 파일 크기 초과 |
| 500 | 서버 내부 오류 |

## 제한사항

- 최대 업로드 파일 크기: 200MB
- 동시 분석 작업: 1개
- API 요청 제한: 없음 (추후 구현 예정)

## 사용 예제

### Python으로 API 호출

```python
import requests

# 세션 생성
session = requests.Session()

# 로그인
login_data = {
    'username': 'admin',
    'password': 'admin'
}
response = session.post('https://localhost:14000/login', 
                       data=login_data, 
                       verify=False)

# 로그 파일 업로드
files = {'logfile': open('firewall.log', 'rb')}
response = session.post('https://localhost:14000/upload', 
                       files=files, 
                       verify=False)

# 분석 실행
analyze_data = {
    'min_occurrences': 1,
    'eps': 0.5,
    'min_samples': 2,
    'max_data_points': 10000
}
response = session.post('https://localhost:14000/api/analyze', 
                       data=analyze_data, 
                       verify=False)

# 결과 확인
result = response.json()
print(f"생성된 정책 수: {result['policies_count']}")
```

### JavaScript로 API 호출

```javascript
// 로그인
fetch('/login', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: 'username=admin&password=admin',
    credentials: 'same-origin'
})
.then(response => {
    if (response.ok) {
        // 로그 분석 실행
        return fetch('/api/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                min_occurrences: 1,
                eps: 0.5,
                min_samples: 2,
                max_data_points: 10000
            }),
            credentials: 'same-origin'
        });
    }
})
.then(response => response.json())
.then(data => {
    console.log(`생성된 정책 수: ${data.policies_count}`);
});
```

## 버전 관리

현재 API 버전: v1.0

향후 버전 업데이트 시 하위 호환성을 유지하며, 새로운 엔드포인트는 `/api/v2/` 형태로 추가될 예정입니다.
