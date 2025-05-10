#!/bin/bash
# 로그 순환 설정 스크립트

# 색상 정의
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 관리자 권한 확인
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}오류: 이 스크립트는 관리자 권한으로 실행해야 합니다.${NC}"
  echo -e "sudo bash $0 명령으로 다시 실행하세요."
  exit 1
fi

CURRENT_DIR=$(pwd)
SERVICE_USER=$(whoami)
SERVICE_GROUP=$(id -gn $SERVICE_USER)

# 사용자 확인
echo -e "${YELLOW}로그 파일 소유자를 입력하세요 (기본: $SERVICE_USER):${NC}"
read INPUT_USER
SERVICE_USER=${INPUT_USER:-$SERVICE_USER}

# 사용자 존재 확인
if ! id "$SERVICE_USER" &>/dev/null; then
    echo -e "${RED}오류: 사용자 '$SERVICE_USER'가 존재하지 않습니다.${NC}"
    exit 1
fi

# 그룹 확인
SERVICE_GROUP=$(id -gn $SERVICE_USER)
echo -e "${YELLOW}로그 파일 소유 그룹을 입력하세요 (기본: $SERVICE_GROUP):${NC}"
read INPUT_GROUP
SERVICE_GROUP=${INPUT_GROUP:-$SERVICE_GROUP}

# 그룹 존재 확인
if ! getent group "$SERVICE_GROUP" >/dev/null; then
    echo -e "${RED}오류: 그룹 '$SERVICE_GROUP'이 존재하지 않습니다.${NC}"
    exit 1
fi

# 로그 디렉토리 확인 및 생성
LOG_DIR="$CURRENT_DIR/logs"
if [ ! -d "$LOG_DIR" ]; then
    echo -e "${YELLOW}로그 디렉토리가 존재하지 않습니다. 생성합니다...${NC}"
    mkdir -p "$LOG_DIR"
    chown $SERVICE_USER:$SERVICE_GROUP "$LOG_DIR"
fi

# logrotate 설치 확인
if ! command -v logrotate &> /dev/null; then
    echo -e "${YELLOW}logrotate가 설치되어 있지 않습니다. 설치를 시작합니다...${NC}"
    apt-get update && apt-get install -y logrotate
fi

# logrotate 설정 파일 생성
echo -e "${GREEN}logrotate 설정 파일 생성 중...${NC}"
cat > /etc/logrotate.d/juniper-policy-recommender << EOF
$LOG_DIR/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 $SERVICE_USER $SERVICE_GROUP
    sharedscripts
    postrotate
        systemctl reload juniper-policy-recommender.service >/dev/null 2>&1 || true
    endscript
}
EOF

echo -e "\n${GREEN}logrotate 설정이 완료되었습니다.${NC}"
echo -e "로그 파일은 다음과 같이 관리됩니다:"
echo -e "  - 로그 위치: ${YELLOW}$LOG_DIR/*.log${NC}"
echo -e "  - 로그 소유자: ${YELLOW}$SERVICE_USER:$SERVICE_GROUP${NC}"
echo -e "  - 로그 보관 기간: ${YELLOW}14일${NC}"
echo -e "  - 로그 순환 주기: ${YELLOW}매일${NC}"
echo -e "\n로그 순환은 자동으로 실행됩니다. 수동으로 실행하려면:"
echo -e "  ${YELLOW}sudo logrotate -f /etc/logrotate.d/juniper-policy-recommender${NC}"