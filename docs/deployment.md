# 배포 가이드

이 문서는 방화벽 정책 추천 시스템을 프로덕션 환경에 배포하는 방법을 설명합니다.

## 배포 옵션

1. [독립 실행형 배포](#독립-실행형-배포)
2. [systemd 서비스 배포](#systemd-서비스-배포)
3. [Docker 컨테이너 배포](#docker-컨테이너-배포)
4. [Kubernetes 배포](#kubernetes-배포)
5. [클라우드 배포](#클라우드-배포)

## 독립 실행형 배포

가장 간단한 배포 방법으로, 직접 Python 스크립트를 실행합니다.

### 1. 프로덕션 설정

```python
# config/config.py 수정
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-strong-secret-key'
    DEBUG = False
    TESTING = False
```

### 2. Gunicorn으로 실행

```bash
# Gunicorn 설치
pip install gunicorn

# 실행
gunicorn -w 4 -b 0.0.0.0:14000 --certfile ssl/cert.pem --keyfile ssl/key.pem app:app
```

### 3. 프로세스 관리 (PM2)

```bash
# PM2 설치
npm install -g pm2

# ecosystem.config.js 생성
module.exports = {
  apps: [{
    name: 'firewall-policy-recommender',
    script: 'app.py',
    interpreter: 'python3',
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: '1G',
    env: {
      PORT: 14000,
      NODE_ENV: 'production'
    }
  }]
};

# 실행
pm2 start ecosystem.config.js
```

## systemd 서비스 배포

Linux 시스템에서 자동 시작 및 관리를 위한 방법입니다.

### 1. 서비스 파일 생성

```bash
sudo nano /etc/systemd/system/firewall-policy-recommender.service
```

```ini
[Unit]
Description=Firewall Policy Recommender
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/opt/firewall-policy-recommender
Environment="PATH=/opt/firewall-policy-recommender/venv/bin"
ExecStart=/opt/firewall-policy-recommender/venv/bin/gunicorn \
    -w 4 \
    -b 0.0.0.0:14000 \
    --certfile ssl/cert.pem \
    --keyfile ssl/key.pem \
    --access-logfile /var/log/firewall-policy-recommender/access.log \
    --error-logfile /var/log/firewall-policy-recommender/error.log \
    app:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### 2. 서비스 활성화

```bash
# 로그 디렉토리 생성
sudo mkdir -p /var/log/firewall-policy-recommender
sudo chown www-data:www-data /var/log/firewall-policy-recommender

# 서비스 활성화 및 시작
sudo systemctl daemon-reload
sudo systemctl enable firewall-policy-recommender
sudo systemctl start firewall-policy-recommender
```

### 3. 로그 로테이션 설정

```bash
sudo nano /etc/logrotate.d/firewall-policy-recommender
```

```
/var/log/firewall-policy-recommender/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 640 www-data www-data
    sharedscripts
    postrotate
        systemctl reload firewall-policy-recommender > /dev/null 2>&1 || true
    endscript
}
```

## Docker 컨테이너 배포

### 1. Dockerfile 생성

```dockerfile
FROM python:3.9-slim

# 시스템 의존성 설치
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 작업 디렉토리 설정
WORKDIR /app

# 의존성 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 애플리케이션 복사
COPY . .

# 필요한 디렉토리 생성
RUN mkdir -p logs static/output ssl flask_sessions config

# 포트 노출
EXPOSE 14000
EXPOSE 514/udp

# 실행
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:14000", "app:app"]
```

### 2. Docker Compose 설정

```yaml
version: '3.8'

services:
  app:
    build: .
    container_name: firewall-policy-recommender
    ports:
      - "14000:14000"
      - "514:514/udp"
    volumes:
      - ./logs:/app/logs
      - ./static/output:/app/static/output
      - ./config:/app/config
      - ./ssl:/app/ssl:ro
    environment:
      - FLASK_ENV=production
      - SECRET_KEY=${SECRET_KEY}
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:14000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  nginx:
    image: nginx:alpine
    container_name: nginx-proxy
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - app
    restart: unless-stopped
```

### 3. Nginx 설정

```nginx
events {
    worker_connections 1024;
}

http {
    upstream app {
        server app:14000;
    }
    
    server {
        listen 80;
        server_name your-domain.com;
        return 301 https://$server_name$request_uri;
    }
    
    server {
        listen 443 ssl;
        server_name your-domain.com;
        
        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        
        location / {
            proxy_pass http://app;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
        
        location /static {
            alias /app/static;
            expires 30d;
        }
    }
}
```

### 4. 배포 실행

```bash
# 빌드 및 실행
docker-compose up -d

# 로그 확인
docker-compose logs -f

# 중지
docker-compose down
```

## Kubernetes 배포

### 1. Deployment 설정

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: firewall-policy-recommender
spec:
  replicas: 2
  selector:
    matchLabels:
      app: firewall-policy-recommender
  template:
    metadata:
      labels:
        app: firewall-policy-recommender
    spec:
      containers:
      - name: app
        image: your-registry/firewall-policy-recommender:latest
        ports:
        - containerPort: 14000
        - containerPort: 514
          protocol: UDP
        env:
        - name: FLASK_ENV
          value: "production"
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: secret-key
        volumeMounts:
        - name: logs
          mountPath: /app/logs
        - name: config
          mountPath: /app/config
        livenessProbe:
          httpGet:
            path: /health
            port: 14000
          initialDelaySeconds: 30
          periodSeconds: 30
      volumes:
      - name: logs
        persistentVolumeClaim:
          claimName: logs-pvc
      - name: config
        configMap:
          name: app-config
```

### 2. Service 설정

```yaml
apiVersion: v1
kind: Service
metadata:
  name: firewall-policy-recommender
spec:
  selector:
    app: firewall-policy-recommender
  ports:
  - name: http
    port: 14000
    targetPort: 14000
  - name: syslog
    port: 514
    targetPort: 514
    protocol: UDP
  type: LoadBalancer
```

### 3. ConfigMap 및 Secret

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  config.py: |
    class Config:
        # 설정 내용

---
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
type: Opaque
data:
  secret-key: <base64-encoded-secret>
```

### 4. 배포 실행

```bash
# 네임스페이스 생성
kubectl create namespace firewall-policy

# 리소스 적용
kubectl apply -f deployment.yaml -n firewall-policy
kubectl apply -f service.yaml -n firewall-policy
kubectl apply -f configmap.yaml -n firewall-policy
kubectl apply -f secret.yaml -n firewall-policy

# 상태 확인
kubectl get pods -n firewall-policy
kubectl get svc -n firewall-policy
```

## 클라우드 배포

### AWS EC2 배포

```bash
# EC2 인스턴스 설정
sudo apt update
sudo apt install -y python3.9 python3.9-venv nginx

# 애플리케이션 설정
cd /opt
sudo git clone https://github.com/your-repo/firewall-policy-recommender.git
cd firewall-policy-recommender
sudo python3.9 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Nginx 설정
sudo nano /etc/nginx/sites-available/firewall-policy-recommender
```

### AWS ECS 배포

```json
{
  "family": "firewall-policy-recommender",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "executionRoleArn": "arn:aws:iam::xxx:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "app",
      "image": "xxx.dkr.ecr.region.amazonaws.com/firewall-policy-recommender:latest",
      "portMappings": [
        {
          "containerPort": 14000,
          "protocol": "tcp"
        },
        {
          "containerPort": 514,
          "protocol": "udp"
        }
      ],
      "environment": [
        {
          "name": "FLASK_ENV",
          "value": "production"
        }
      ],
      "secrets": [
        {
          "name": "SECRET_KEY",
          "valueFrom": "arn:aws:secretsmanager:region:xxx:secret:app-secrets"
        }
      ]
    }
  ]
}
```

### Google Cloud Run 배포

```bash
# Container Registry에 이미지 푸시
gcloud builds submit --tag gcr.io/project-id/firewall-policy-recommender

# Cloud Run 배포
gcloud run deploy firewall-policy-recommender \
  --image gcr.io/project-id/firewall-policy-recommender \
  --platform managed \
  --port 14000 \
  --allow-unauthenticated
```

## 모니터링 및 로깅

### 1. Prometheus 메트릭

```python
# app.py에 메트릭 추가
from prometheus_client import Counter, Histogram, generate_latest

REQUEST_COUNT = Counter('app_requests_total', 'Total app requests')
REQUEST_LATENCY = Histogram('app_request_latency_seconds', 'Request latency')

@app.route('/metrics')
def metrics():
    return generate_latest()
```

### 2. ELK Stack 로깅

```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/firewall-policy-recommender/*.log

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
```

### 3. Health Check 엔드포인트

```python
@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })
```

## 보안 고려사항

### 1. SSL/TLS 설정

```bash
# Let's Encrypt 인증서 발급
sudo certbot certonly --standalone -d your-domain.com

# 자동 갱신 설정
sudo certbot renew --dry-run
```

### 2. 보안 헤더 설정

```python
from flask_talisman import Talisman

Talisman(app, 
    force_https=True,
    strict_transport_security=True,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline'",
        'style-src': "'self' 'unsafe-inline'"
    }
)
```

### 3. Rate Limiting

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
```

## 백업 및 복구

### 1. 자동 백업 스크립트

```bash
#!/bin/bash
BACKUP_DIR="/backup/firewall-policy-recommender"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR/$DATE

# 설정 파일 백업
cp -r config/* $BACKUP_DIR/$DATE/config/

# 로그 백업
tar czf $BACKUP_DIR/$DATE/logs.tar.gz logs/

# 분석 결과 백업
tar czf $BACKUP_DIR/$DATE/output.tar.gz static/output/

# 오래된 백업 삭제 (30일 이상)
find $BACKUP_DIR -type d -mtime +30 -exec rm -rf {} \;
```

### 2. 복구 절차

```bash
# 백업에서 복구
cd /opt/firewall-policy-recommender
tar xzf /backup/firewall-policy-recommender/20240101_120000/logs.tar.gz
tar xzf /backup/firewall-policy-recommender/20240101_120000/output.tar.gz
cp -r /backup/firewall-policy-recommender/20240101_120000/config/* config/

# 서비스 재시작
sudo systemctl restart firewall-policy-recommender
```

## 성능 튜닝

### 1. Gunicorn 워커 최적화

```python
# gunicorn.conf.py
import multiprocessing

workers = multiprocessing.cpu_count() * 2 + 1
worker_class = 'gevent'
worker_connections = 1000
timeout = 30
keepalive = 2
max_requests = 1000
max_requests_jitter = 50
```

### 2. 캐싱 설정

```python
from flask_caching import Cache

cache = Cache(app, config={
    'CACHE_TYPE': 'redis',
    'CACHE_REDIS_URL': 'redis://localhost:6379/0'
})

@app.route('/api/analyze')
@cache.cached(timeout=300)
def analyze():
    # 분석 로직
```

### 3. 데이터베이스 연결 풀

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

engine = create_engine(
    'postgresql://user:pass@localhost/db',
    pool_size=10,
    pool_pre_ping=True,
    pool_recycle=3600
)
```

## 문제 해결

### 1. 배포 체크리스트

- [ ] 비밀번호 변경 완료
- [ ] SSL 인증서 설치
- [ ] 방화벽 규칙 설정
- [ ] 백업 스크립트 설정
- [ ] 모니터링 설정
- [ ] 로그 로테이션 설정

### 2. 일반적인 문제

- **포트 충돌**: 다른 서비스가 포트를 사용 중인지 확인
- **권한 문제**: 파일 및 디렉토리 권한 확인
- **메모리 부족**: 시스템 리소스 모니터링

### 3. 롤백 절차

```bash
# 이전 버전으로 롤백
cd /opt/firewall-policy-recommender
git checkout v1.0.0
source venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart firewall-policy-recommender
```

## 배포 자동화

### GitHub Actions

```yaml
name: Deploy

on:
  push:
    branches: [ main ]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    
    - name: Deploy to server
      uses: appleboy/ssh-action@master
      with:
        host: ${{ secrets.HOST }}
        username: ${{ secrets.USERNAME }}
        key: ${{ secrets.SSH_KEY }}
        script: |
          cd /opt/firewall-policy-recommender
          git pull
          source venv/bin/activate
          pip install -r requirements.txt
          sudo systemctl restart firewall-policy-recommender
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('Build') {
            steps {
                sh 'python -m venv venv'
                sh '. venv/bin/activate && pip install -r requirements.txt'
            }
        }
        
        stage('Test') {
            steps {
                sh '. venv/bin/activate && pytest'
            }
        }
        
        stage('Deploy') {
            steps {
                sh 'sudo systemctl restart firewall-policy-recommender'
            }
        }
    }
}
```
