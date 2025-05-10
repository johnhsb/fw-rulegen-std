# 설치 가이드

이 문서는 방화벽 정책 추천 시스템의 상세한 설치 과정을 설명합니다.

## 시스템 요구사항

### 최소 요구사항
- Python 3.8 이상
- 4GB RAM
- 1GB 디스크 여유 공간
- 최신 웹 브라우저 (Chrome, Firefox, Safari, Edge)

### 권장 사양
- Python 3.9 이상
- 8GB RAM (대용량 로그 분석 시)
- 5GB 디스크 여유 공간
- SSD 스토리지

### 운영체제
- Ubuntu 20.04 LTS 이상
- CentOS 7/8, RHEL 7/8
- Windows 10/11
- macOS 10.15 이상

## 사전 준비사항

### 1. Python 설치

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install python3.9 python3.9-venv python3.9-dev
```

#### CentOS/RHEL
```bash
sudo yum install python39 python39-devel
```

#### Windows
[Python 공식 웹사이트](https://www.python.org/downloads/)에서 설치 프로그램 다운로드

#### macOS
```bash
brew install python@3.9
```

### 2. Git 설치 (선택사항)
```bash
# Ubuntu/Debian
sudo apt install git

# CentOS/RHEL
sudo yum install git

# macOS
brew install git
```

## 설치 과정

### 1. 소스코드 다운로드

#### Git을 사용하는 경우
```bash
git clone https://github.com/your-username/firewall-policy-recommender.git
cd firewall-policy-recommender
```

#### 직접 다운로드
1. GitHub에서 ZIP 파일 다운로드
2. 원하는 위치에 압축 해제
3. 터미널에서 해당 디렉토리로 이동

### 2. 가상환경 생성 및 활성화

```bash
# 가상환경 생성
python3 -m venv venv

# 가상환경 활성화
# Linux/macOS
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### 3. 의존성 패키지 설치

```bash
# pip 업그레이드
pip install --upgrade pip

# 의존성 설치
pip install -r requirements.txt
```

### 4. 디렉토리 구조 확인 및 생성

```bash
# 필요한 디렉토리 생성
mkdir -p logs
mkdir -p static/output
mkdir -p ssl
mkdir -p flask_sessions
mkdir -p config
```

### 5. 초기 설정

#### 기본 사용자 설정
```bash
# config/users.json 파일 생성 (자동으로 생성됨)
# 또는 수동으로 생성:
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

#### SSL 인증서 생성 (선택사항)
```bash
# 자체 서명 인증서 생성 (개발/테스트용)
openssl req -x509 -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem -days 365 -nodes -subj "/CN=localhost"

# 프로덕션의 경우 공인 인증서 사용 권장
```

### 6. 방화벽 설정 (Syslog 수신용)

#### Ubuntu/Debian (UFW)
```bash
sudo ufw allow 514/udp  # Syslog
sudo ufw allow 14000/tcp  # 웹 서버
```

#### CentOS/RHEL (firewalld)
```bash
sudo firewall-cmd --permanent --add-port=514/udp
sudo firewall-cmd --permanent --add-port=14000/tcp
sudo firewall-cmd --reload
```

### 7. 서비스 실행

#### 개발 모드
```bash
python app.py
```

#### 프로덕션 모드
```bash
python app.py --host 0.0.0.0 --port 14000
```

## 서비스 등록 (systemd)

프로덕션 환경에서는 systemd 서비스로 등록하는 것을 권장합니다.

### 1. 서비스 파일 생성

```bash
sudo nano /etc/systemd/system/firewall-policy-recommender.service
```

### 2. 서비스 파일 내용

```ini
[Unit]
Description=Firewall Policy Recommender
After=network.target

[Service]
Type=simple
User=your-username
WorkingDirectory=/path/to/firewall-policy-recommender
Environment="PATH=/path/to/firewall-policy-recommender/venv/bin"
ExecStart=/path/to/firewall-policy-recommender/venv/bin/python app.py --host 0.0.0.0 --port 14000
Restart=always

[Install]
WantedBy=multi-user.target
```

### 3. 서비스 활성화 및 시작

```bash
# 서비스 리로드
sudo systemctl daemon-reload

# 서비스 활성화
sudo systemctl enable firewall-policy-recommender

# 서비스 시작
sudo systemctl start firewall-policy-recommender

# 상태 확인
sudo systemctl status firewall-policy-recommender
```

## 환경 변수 설정

`.env` 파일을 생성하여 환경별 설정을 관리할 수 있습니다:

```bash
# .env 파일 예시
FLASK_ENV=production
SECRET_KEY=your-secret-key-here
MAX_UPLOAD_SIZE=200
SYSLOG_PORT=514
WEB_PORT=14000
```

## Docker 설치 (선택사항)

### Dockerfile
```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p logs static/output ssl flask_sessions config

EXPOSE 14000 514/udp

CMD ["python", "app.py", "--host", "0.0.0.0", "--port", "14000"]
```

### Docker Compose
```yaml
version: '3.8'

services:
  firewall-policy-recommender:
    build: .
    ports:
      - "14000:14000"
      - "514:514/udp"
    volumes:
      - ./logs:/app/logs
      - ./static/output:/app/static/output
      - ./config:/app/config
    restart: unless-stopped
```

## 설치 확인

1. 웹 브라우저에서 https://localhost:14000 접속
2. 기본 계정으로 로그인 (admin/admin)
3. 대시보드가 정상적으로 표시되는지 확인

## 문제 해결

### 포트 충돌
```bash
# 사용 중인 포트 확인
netstat -tulpn | grep 14000
netstat -tulpn | grep 514

# 다른 포트로 변경
python app.py --port 15000
```

### 권한 문제
```bash
# 로그 디렉토리 권한 설정
chmod -R 755 logs
chmod -R 755 static/output

# Syslog 수신 권한 (1024 이하 포트)
sudo setcap 'cap_net_bind_service=+ep' $(which python3)
```

### 메모리 부족
```bash
# 스왑 메모리 추가 (Ubuntu/Debian)
sudo dd if=/dev/zero of=/swapfile bs=1G count=4
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

## 업그레이드

```bash
# 최신 코드 가져오기
git pull origin main

# 가상환경 활성화
source venv/bin/activate

# 의존성 업데이트
pip install -r requirements.txt --upgrade

# 서비스 재시작
sudo systemctl restart firewall-policy-recommender
```

## 백업

정기적인 백업을 위해 다음 디렉토리들을 백업하세요:

- `config/` - 설정 파일
- `logs/` - 수집된 로그
- `static/output/` - 분석 결과

## 보안 고려사항

1. 기본 비밀번호를 반드시 변경하세요
2. SSL/TLS를 활성화하세요
3. 방화벽에서 필요한 포트만 열어두세요
4. 정기적으로 시스템을 업데이트하세요
5. 로그 파일에 대한 접근 권한을 제한하세요
