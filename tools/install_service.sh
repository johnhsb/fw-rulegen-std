#!/bin/bash
# Juniper 방화벽 정책 추천 도구 systemd 서비스 등록 스크립트

# 색상 정의
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 현재 디렉토리 경로 가져오기
CURRENT_DIR=$(pwd)
SERVICE_NAME="juniper-policy-recommender"
SERVICE_FILE="${SERVICE_NAME}.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE_FILE}"

# 관리자 권한 확인
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}오류: 이 스크립트는 관리자 권한으로 실행해야 합니다.${NC}"
  echo -e "sudo bash $0 명령으로 다시 실행하세요."
  exit 1
fi

# 필요한 패키지 확인 및 설치
echo -e "${GREEN}시스템 패키지 확인 중...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${YELLOW}Python3가 설치되어 있지 않습니다. 설치를 시작합니다...${NC}"
    apt-get update && apt-get install -y python3 python3-pip
fi

# Python 패키지 설치
echo -e "${GREEN}Python 패키지 설치 중...${NC}"
pip3 install flask flask_session pandas numpy scikit-learn networkx matplotlib plotly

# 사용자 확인
echo -e "${YELLOW}서비스를 실행할 사용자를 입력하세요 (기본: $(whoami)):${NC}"
read SERVICE_USER
SERVICE_USER=${SERVICE_USER:-$(whoami)}

# 사용자 존재 확인
if ! id "$SERVICE_USER" &>/dev/null; then
    echo -e "${RED}오류: 사용자 '$SERVICE_USER'가 존재하지 않습니다.${NC}"
    exit 1
fi

# 포트 설정
echo -e "${YELLOW}웹 서비스 포트를 입력하세요 (기본: 15000):${NC}"
read SERVICE_PORT
SERVICE_PORT=${SERVICE_PORT:-15000}

# 서비스 파일 생성
echo -e "${GREEN}systemd 서비스 파일 생성 중...${NC}"
cat > $SERVICE_PATH << EOF
[Unit]
Description=Juniper Firewall Policy Recommender Service
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$CURRENT_DIR
ExecStart=/usr/bin/python3 $CURRENT_DIR/web_interface.py --host 0.0.0.0 --port $SERVICE_PORT
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME
Environment="PYTHONUNBUFFERED=1"

[Install]
WantedBy=multi-user.target
EOF

# 서비스 등록 및 시작
echo -e "${GREEN}systemd 서비스 등록 및 시작 중...${NC}"
systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME

# 서비스 상태 확인
echo -e "${GREEN}서비스 상태 확인...${NC}"
systemctl status $SERVICE_NAME

echo -e "\n${GREEN}설치 완료!${NC}"
echo -e "서비스 관리 명령어:"
echo -e "  - 서비스 시작: ${YELLOW}sudo systemctl start $SERVICE_NAME${NC}"
echo -e "  - 서비스 중지: ${YELLOW}sudo systemctl stop $SERVICE_NAME${NC}"
echo -e "  - 서비스 재시작: ${YELLOW}sudo systemctl restart $SERVICE_NAME${NC}"
echo -e "  - 서비스 상태 확인: ${YELLOW}sudo systemctl status $SERVICE_NAME${NC}"
echo -e "  - 서비스 로그 확인: ${YELLOW}sudo journalctl -u $SERVICE_NAME${NC}"
echo -e "\n웹 인터페이스는 http://$(hostname -I | awk '{print $1}'):$SERVICE_PORT 에서 접속할 수 있습니다."