# 변경 로그

모든 주요 변경사항은 이 파일에 문서화됩니다.

이 프로젝트는 [Semantic Versioning](https://semver.org/spec/v2.0.0.html)을 준수합니다.

## [Unreleased]

### 추가 예정
- 실시간 웹소켓 기반 로그 모니터링
- 멀티 벤더 방화벽 지원 (Cisco, Fortinet)
- REST API v2 엔드포인트
- 고급 머신러닝 알고리즘 적용
- 대시보드 커스터마이징 기능

## [1.2.0] - 2024-12-31

### 추가
- IPv6 트래픽 분석 지원
- 3D 인터랙티브 트래픽 시각화
- Sankey 다이어그램을 통한 트래픽 흐름 분석
- 다크 테마 UI 전면 적용
- 자동 로그 정리 기능
- 시스템 리소스 모니터링 API

### 변경
- DBSCAN 클러스터링 알고리즘 최적화 (메모리 사용량 50% 감소)
- 로그 파싱 성능 개선 (처리 속도 2배 향상)
- 대용량 파일 업로드 제한을 200MB로 증가
- UI/UX 개선 및 반응형 디자인 적용

### 수정
- Syslog 서버 메모리 누수 문제 해결
- ICMP 프로토콜 파싱 오류 수정
- 세션 타임아웃 관련 버그 수정
- 필터링 로직의 엣지 케이스 처리

### 보안
- SQL 인젝션 취약점 패치
- XSS 공격 방지 기능 강화
- 비밀번호 해싱 알고리즘 업그레이드 (SHA-256)

## [1.1.0] - 2024-11-15

### 추가
- 실시간 Syslog 서버 기능
- 자동 분석 스케줄러
- 다중 필터 지원 (IP, 포트, 프로토콜, 존)
- 분석 결과 내보내기 기능 (JSON, CSV)
- 시스템 설정 관리 페이지

### 변경
- Flask 2.3.3으로 업그레이드
- pandas 2.0.3으로 업그레이드
- scikit-learn 1.3.0으로 업그레이드
- UI 컴포넌트 Bootstrap 5로 마이그레이션

### 수정
- 대용량 로그 파일 처리 시 타임아웃 문제
- 중복 정책 생성 버그
- 날짜 범위 필터 오작동

### 제거
- 레거시 로그 파서 코드
- 사용되지 않는 의존성 패키지

## [1.0.1] - 2024-10-30

### 수정
- 업로드 파일 경로 검증 강화
- 로그인 세션 보안 개선
- 크로스 사이트 스크립팅(XSS) 취약점 수정

### 문서
- API 레퍼런스 문서 추가
- 트러블슈팅 가이드 작성
- 설치 가이드 업데이트

## [1.0.0] - 2024-10-01

### 추가
- 초기 릴리즈
- 주니퍼 방화벽 로그 파싱
- DBSCAN 기반 트래픽 패턴 분석
- 방화벽 정책 자동 생성
- 웹 기반 대시보드
- 사용자 인증 시스템
- 기본 시각화 (테이블, 차트)

### 알려진 이슈
- IPv6 지원 미완성
- 메모리 사용량 최적화 필요
- 대용량 로그 처리 시 성능 저하

## 버전 비교

[Unreleased]: https://github.com/username/firewall-policy-recommender/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/username/firewall-policy-recommender/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/username/firewall-policy-recommender/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/username/firewall-policy-recommender/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/username/firewall-policy-recommender/releases/tag/v1.0.0

## 마이그레이션 가이드

### v1.1.0에서 v1.2.0으로

1. 새로운 의존성 설치:
```bash
pip install -r requirements.txt --upgrade
```

2. 데이터베이스 스키마 변경사항 없음

3. 설정 파일 업데이트:
- `config/config.py`에서 새로운 설정 항목 확인
- IPv6 관련 설정 추가 가능

4. UI 변경사항:
- 다크 테마가 기본으로 적용됨
- 기존 커스텀 CSS는 재검토 필요

### v1.0.x에서 v1.1.0으로

1. Flask 및 주요 라이브러리 업그레이드:
```bash
pip install -r requirements.txt --upgrade
```

2. 새로운 디렉토리 구조:
```bash
mkdir -p logs/syslog
mkdir -p static/output/syslog
```

3. Syslog 서버 설정:
- 시스템 방화벽에서 UDP 514 포트 개방
- `syslog_config` 섹션 추가

4. 웹 템플릿 변경:
- Bootstrap 4에서 5로 마이그레이션
- 일부 CSS 클래스 이름 변경

## 개발 로드맵

### 단기 계획 (3개월)
- [ ] 웹소켓 기반 실시간 로그 스트리밍
- [ ] 정책 버전 관리 기능
- [ ] 사용자 역할 기반 접근 제어 (RBAC)
- [ ] 대시보드 위젯 커스터마이징

### 중기 계획 (6개월)
- [ ] 멀티 벤더 방화벽 지원
- [ ] 머신러닝 기반 이상 탐지
- [ ] 정책 시뮬레이션 기능
- [ ] 클라우드 네이티브 배포 지원

### 장기 계획 (12개월)
- [ ] 마이크로서비스 아키텍처로 전환
- [ ] GraphQL API 지원
- [ ] 모바일 앱 개발
- [ ] SaaS 버전 출시
