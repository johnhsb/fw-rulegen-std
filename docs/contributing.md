# 기여 가이드

방화벽 정책 추천 시스템 프로젝트에 기여해주셔서 감사합니다! 이 문서는 프로젝트 기여 방법과 가이드라인을 설명합니다.

## 목차

1. [시작하기](#시작하기)
2. [개발 환경 설정](#개발-환경-설정)
3. [코딩 표준](#코딩-표준)
4. [커밋 메시지 규칙](#커밋-메시지-규칙)
5. [Pull Request 프로세스](#pull-request-프로세스)
6. [이슈 보고](#이슈-보고)
7. [테스트 작성](#테스트-작성)
8. [문서화](#문서화)

## 시작하기

### 1. 저장소 포크 및 클론

```bash
# 저장소 포크 (GitHub 웹사이트에서)
# 포크한 저장소 클론
git clone https://github.com/your-username/firewall-policy-recommender.git
cd firewall-policy-recommender

# 업스트림 저장소 추가
git remote add upstream https://github.com/original-owner/firewall-policy-recommender.git
```

### 2. 브랜치 생성

```bash
# 최신 코드 가져오기
git fetch upstream
git checkout main
git merge upstream/main

# 새 기능 브랜치 생성
git checkout -b feature/your-feature-name
```

## 개발 환경 설정

### 1. 가상환경 설정

```bash
# 가상환경 생성
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 개발 의존성 설치
pip install -r requirements-dev.txt
```

### 2. 개발 도구 설정

```bash
# pre-commit 훅 설치
pip install pre-commit
pre-commit install

# 코드 포매터 및 린터 설정
pip install black flake8 mypy
```

### 3. 환경 변수 설정

```bash
# .env.development 파일 생성
cp .env.example .env.development

# 개발용 설정
export FLASK_ENV=development
export FLASK_DEBUG=1
```

## 코딩 표준

### Python 스타일 가이드

- PEP 8 준수
- 최대 줄 길이: 88자 (Black 기본값)
- 들여쓰기: 공백 4칸

### 코드 포매팅

```bash
# Black으로 자동 포매팅
black .

# 특정 파일만 포매팅
black modules/traffic_analyzer.py
```

### 린팅

```bash
# Flake8으로 코드 검사
flake8 .

# MyPy로 타입 검사
mypy .
```

### 명명 규칙

```python
# 클래스명: PascalCase
class TrafficAnalyzer:
    pass

# 함수명: snake_case
def analyze_traffic_patterns():
    pass

# 상수: UPPER_SNAKE_CASE
MAX_CLUSTER_SIZE = 1000

# 비공개 함수/변수: 언더스코어 접두사
def _internal_function():
    pass
```

### Docstring 작성

```python
def cluster_traffic_patterns(self, data: pd.DataFrame) -> pd.DataFrame:
    """
    트래픽 패턴을 클러스터링합니다.
    
    Args:
        data (pd.DataFrame): 정규화된 로그 데이터
        
    Returns:
        pd.DataFrame: 클러스터 레이블이 추가된 데이터프레임
        
    Raises:
        ValueError: 데이터가 비어있을 경우
        
    Examples:
        >>> analyzer = TrafficAnalyzer()
        >>> result = analyzer.cluster_traffic_patterns(log_df)
    """
    if data.empty:
        raise ValueError("데이터가 비어있습니다")
    
    # 구현 내용
```

## 커밋 메시지 규칙

### 형식

```
<타입>(<범위>): <제목>

<본문>

<푸터>
```

### 타입

- `feat`: 새로운 기능
- `fix`: 버그 수정
- `docs`: 문서 변경
- `style`: 코드 포맷팅, 세미콜론 누락 등
- `refactor`: 코드 리팩토링
- `test`: 테스트 추가 또는 수정
- `chore`: 빌드, 패키지 매니저 설정 등

### 예시

```
feat(analysis): Add IPv6 support for traffic analysis

- Implement IPv6 address parsing
- Update DBSCAN clustering for IPv6
- Add unit tests for IPv6 functionality

Closes #123
```

## Pull Request 프로세스

### 1. PR 생성 전 체크리스트

- [ ] 코드가 코딩 표준을 준수하는지 확인
- [ ] 모든 테스트가 통과하는지 확인
- [ ] 문서를 업데이트했는지 확인
- [ ] 커밋 메시지가 규칙을 따르는지 확인

### 2. PR 템플릿

```markdown
## 설명
이 PR이 해결하는 문제나 추가하는 기능에 대한 간단한 설명

## 변경 사항
- 주요 변경 사항 목록
- 구현 세부 사항

## 테스트 방법
1. 테스트 실행 방법
2. 예상 결과

## 체크리스트
- [ ] 코드 리뷰 요청 전 자체 리뷰 완료
- [ ] 단위 테스트 추가/수정
- [ ] 문서 업데이트
- [ ] 변경 로그 업데이트

## 관련 이슈
Closes #123
```

### 3. 코드 리뷰 프로세스

1. PR 생성 후 리뷰어 지정
2. 리뷰어의 피드백 반영
3. CI/CD 파이프라인 통과 확인
4. 최소 1명의 승인 필요
5. 메인테이너가 최종 머지

## 이슈 보고

### 버그 리포트 템플릿

```markdown
## 버그 설명
버그에 대한 명확하고 간결한 설명

## 재현 방법
1. '...'로 이동
2. '...'를 클릭
3. '...'까지 스크롤
4. 오류 확인

## 예상 동작
정상적으로 작동했을 때의 예상 결과

## 실제 동작
실제로 발생한 결과

## 스크린샷
해당되는 경우 스크린샷 첨부

## 환경
- OS: [예: Ubuntu 20.04]
- Python 버전: [예: 3.9.5]
- 브라우저: [예: Chrome 100]

## 추가 정보
문제 해결에 도움이 될 수 있는 기타 정보
```

### 기능 요청 템플릿

```markdown
## 기능 설명
제안하는 기능에 대한 명확한 설명

## 사용 사례
이 기능이 필요한 이유와 사용 시나리오

## 제안하는 구현 방법
기능 구현에 대한 아이디어 (선택사항)

## 대안
고려해본 다른 방법들

## 추가 정보
기능 요청과 관련된 기타 정보
```

## 테스트 작성

### 단위 테스트

```python
# tests/test_traffic_analyzer.py
import pytest
from modules.traffic_analyzer import TrafficAnalyzer

class TestTrafficAnalyzer:
    def setup_method(self):
        """각 테스트 전에 실행"""
        self.analyzer = TrafficAnalyzer()
    
    def test_ip_to_int_ipv4(self):
        """IPv4 주소 변환 테스트"""
        result = self.analyzer.ip_to_int("192.168.1.1")
        assert result == 3232235777
    
    def test_ip_to_int_ipv6(self):
        """IPv6 주소 변환 테스트"""
        result = self.analyzer.ip_to_int("2001:db8::1")
        assert result > 0
    
    @pytest.mark.parametrize("ip,expected", [
        ("192.168.1.1", 3232235777),
        ("10.0.0.1", 167772161),
    ])
    def test_ip_conversion(self, ip, expected):
        """파라미터화된 테스트"""
        assert self.analyzer.ip_to_int(ip) == expected
```

### 통합 테스트

```python
# tests/test_integration.py
import pytest
from app import app

class TestAPIIntegration:
    def setup_method(self):
        """테스트 클라이언트 설정"""
        self.app = app.test_client()
        self.app.testing = True
    
    def test_login_success(self):
        """로그인 성공 테스트"""
        response = self.app.post('/login', data={
            'username': 'admin',
            'password': 'admin'
        })
        assert response.status_code == 302
    
    def test_analyze_api(self):
        """분석 API 테스트"""
        # 로그인
        self.app.post('/login', data={
            'username': 'admin',
            'password': 'admin'
        })
        
        # 분석 실행
        response = self.app.post('/api/analyze', data={
            'min_occurrences': 1,
            'eps': 0.5
        })
        assert response.status_code == 200
```

### 테스트 실행

```bash
# 모든 테스트 실행
pytest

# 특정 파일 테스트
pytest tests/test_traffic_analyzer.py

# 커버리지 확인
pytest --cov=modules tests/

# HTML 커버리지 리포트 생성
pytest --cov=modules --cov-report=html tests/
```

## 문서화

### API 문서화

```python
@app.route('/api/analyze', methods=['POST'])
def api_analyze_logs():
    """
    로그 분석 API 엔드포인트
    
    Request Body:
        - min_occurrences (int): 최소 발생 횟수
        - eps (float): DBSCAN epsilon 값
        - min_samples (int): 최소 샘플 수
        
    Returns:
        JSON: {
            'success': bool,
            'policies_count': int,
            'timestamp': str
        }
        
    Status Codes:
        200: 성공
        400: 잘못된 요청
        500: 서버 오류
    """
```

### README 업데이트

- 새로운 기능 추가 시 README.md 업데이트
- 설치 방법 변경 시 INSTALL.md 업데이트
- API 변경 시 API_REFERENCE.md 업데이트

### 변경 로그

```markdown
# CHANGELOG.md

## [Unreleased]

### Added
- IPv6 트래픽 분석 지원
- 실시간 로그 모니터링 대시보드

### Changed
- DBSCAN 알고리즘 성능 최적화
- UI 반응형 디자인 개선

### Fixed
- 메모리 누수 문제 해결
- Syslog 파싱 오류 수정
```

## 개발 워크플로우

### 1. 기능 개발

```bash
# 1. 최신 코드 동기화
git checkout main
git pull upstream main

# 2. 기능 브랜치 생성
git checkout -b feature/new-feature

# 3. 개발 및 커밋
git add .
git commit -m "feat: Add new feature"

# 4. 테스트 실행
pytest

# 5. 푸시
git push origin feature/new-feature
```

### 2. 버그 수정

```bash
# 1. 버그 수정 브랜치 생성
git checkout -b fix/bug-description

# 2. 수정 및 테스트
# ... 코드 수정 ...
pytest tests/

# 3. 커밋 및 푸시
git commit -m "fix: Resolve issue with ..."
git push origin fix/bug-description
```

## 릴리즈 프로세스

### 1. 버전 태깅

```bash
# 버전 태그 생성
git tag -a v1.2.0 -m "Release version 1.2.0"

# 태그 푸시
git push upstream v1.2.0
```

### 2. 릴리즈 노트 작성

- 주요 변경 사항 요약
- 새로운 기능 설명
- 버그 수정 목록
- 마이그레이션 가이드 (필요한 경우)

## 지원 및 커뮤니케이션

### Discord/Slack 채널

프로젝트 관련 논의를 위한 커뮤니케이션 채널 정보

### 정기 미팅

- 주간 개발 미팅: 매주 월요일 10:00 AM
- 월간 로드맵 리뷰: 매월 첫째 주 금요일

## 행동 강령

- 모든 참여자를 존중하세요
- 건설적인 비판과 피드백을 제공하세요
- 다양성과 포용성을 중시하세요
- 전문적이고 협력적인 태도를 유지하세요

## 라이선스

기여하신 코드는 프로젝트의 MIT 라이선스 하에 배포됩니다.

## 감사의 말

프로젝트에 기여해주신 모든 분들께 감사드립니다!

### 기여자 목록

- [@username1](https://github.com/username1) - 핵심 기능 구현
- [@username2](https://github.com/username2) - 문서화 및 테스트
- [@username3](https://github.com/username3) - 버그 수정 및 최적화

---

질문이나 제안사항이 있으시면 이슈를 생성하거나 프로젝트 메인테이너에게 연락해주세요.
