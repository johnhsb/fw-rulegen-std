#!/bin/bash
# Juniper 방화벽 정책 추천 도구 systemd 서비스 관리 스크립트

# 색상 정의
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SERVICE_NAME="juniper-policy-recommender"

# 관리자 권한 확인
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}오류: 이 스크립트는 관리자 권한으로 실행해야 합니다.${NC}"
  echo -e "sudo bash $0 명령으로 다시 실행하세요."
  exit 1
fi

# 도움말 함수
show_help() {
    echo -e "${BLUE}Juniper 방화벽 정책 추천 시스템 서비스 관리${NC}"
    echo -e "사용법: sudo $0 [명령]"
    echo -e "\n명령:"
    echo -e "  ${GREEN}start${NC}    - 서비스 시작"
    echo -e "  ${GREEN}stop${NC}     - 서비스 중지"
    echo -e "  ${GREEN}restart${NC}  - 서비스 재시작"
    echo -e "  ${GREEN}status${NC}   - 서비스 상태 확인"
    echo -e "  ${GREEN}logs${NC}     - 서비스 로그 확인 (Ctrl+C로 종료)"
    echo -e "  ${GREEN}enable${NC}   - 부팅 시 자동 시작 활성화"
    echo -e "  ${GREEN}disable${NC}  - 부팅 시 자동 시작 비활성화"
    echo -e "  ${GREEN}uninstall${NC}- 서비스 제거"
    echo -e "  ${GREEN}help${NC}     - 이 도움말 표시"
}

# 인자 확인
if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

# 명령 실행
case "$1" in
    start)
        echo -e "${GREEN}서비스 시작 중...${NC}"
        systemctl start $SERVICE_NAME
        systemctl status $SERVICE_NAME
        ;;
    stop)
        echo -e "${YELLOW}서비스 중지 중...${NC}"
        systemctl stop $SERVICE_NAME
        systemctl status $SERVICE_NAME
        ;;
    restart)
        echo -e "${GREEN}서비스 재시작 중...${NC}"
        systemctl restart $SERVICE_NAME
        systemctl status $SERVICE_NAME
        ;;
    status)
        echo -e "${BLUE}서비스 상태:${NC}"
        systemctl status $SERVICE_NAME
        ;;
    logs)
        echo -e "${BLUE}서비스 로그 (Ctrl+C로 종료):${NC}"
        journalctl -u $SERVICE_NAME -f
        ;;
    enable)
        echo -e "${GREEN}부팅 시 자동 시작 활성화 중...${NC}"
        systemctl enable $SERVICE_NAME
        echo -e "완료되었습니다."
        ;;
    disable)
        echo -e "${YELLOW}부팅 시 자동 시작 비활성화 중...${NC}"
        systemctl disable $SERVICE_NAME
        echo -e "완료되었습니다."
        ;;
    uninstall)
        echo -e "${RED}서비스 제거 중...${NC}"
        systemctl stop $SERVICE_NAME
        systemctl disable $SERVICE_NAME
        rm -f /etc/systemd/system/${SERVICE_NAME}.service
        systemctl daemon-reload
        echo -e "서비스가 제거되었습니다."
        ;;
    help)
        show_help
        ;;
    *)
        echo -e "${RED}오류: 알 수 없는 명령입니다.${NC}"
        show_help
        exit 1
        ;;
esac

exit 0