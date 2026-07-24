# Tiny Second-hand Shopping Platform

인천대학교 소프트웨어개발실습 과제 - 시큐어코딩을 적용한 중고거래 플랫폼입니다.

## 주요 기능

- 회원가입 / 로그인 / 로그아웃 (비밀번호 해시 저장, 로그인 실패 잠금)
- 마이페이지 (소개글 수정, 비밀번호 변경, 내가 등록한 상품 관리)
- 다른 사용자 프로필 조회
- 상품 등록(사진 업로드 포함) / 조회 / 검색 / 수정 / 삭제
- 실시간 전체 채팅 및 1:1 채팅 (Flask-SocketIO)
- 사용자/상품 신고 및 신고 누적 시 자동 차단(상품)·휴면 전환(사용자)
- 사용자 간 송금 (비밀번호 재확인 포함)
- 관리자 페이지 (사용자 상태 변경, 상품 차단/활성화, 신고 내역 관리)

## 환경 설정

리눅스 환경(WSL/VMWare/VirtualBox 등을 통한 Ubuntu)에서 진행하는 것을 권장합니다.

1. 이 저장소를 클론합니다.

   ```bash
   git clone <이 저장소 URL>
   cd secure-coding
   ```

2. miniconda(또는 anaconda)가 없다면 설치합니다.
   https://docs.anaconda.com/free/miniconda/index.html

3. 가상환경을 생성하고 활성화합니다.

   ```bash
   conda env create -f enviroments.yaml
   conda activate secure_coding
   ```

## 실행 방법

```bash
python app.py
```

서버는 기본적으로 `http://127.0.0.1:5000` 에서 실행됩니다.

> 이전 버전에서 생성된 `market.db`가 남아 있다면, 스키마가 다를 수 있으므로 삭제 후 다시 실행하세요(자동으로 새 DB가 생성됩니다). `market.db`는 `.gitignore` 대상이라 저장소에는 포함되지 않습니다.

외부에서 접속 테스트가 필요하면 ngrok을 사용할 수 있습니다.

```bash
# optional
sudo snap install ngrok
ngrok http 5000
```

### 기본 관리자 계정

최초 실행 시 관리자 계정(`admin`)이 자동으로 생성됩니다. 비밀번호는 소스코드에 하드코딩되어 있지 않습니다.

- 환경변수 `ADMIN_PASSWORD`를 지정하면 해당 값이 관리자 비밀번호로 설정됩니다.
- 지정하지 않으면 최초 실행 시 **무작위 비밀번호가 생성되어 콘솔에 1회만 출력**됩니다. 이 값을 기록해 두고, 로그인 후 마이페이지에서 즉시 변경하세요.

```bash
# 예: 관리자 비밀번호를 직접 지정해서 실행
ADMIN_PASSWORD='원하는안전한비밀번호1' python app.py
```

### 환경 변수 (선택)

| 변수 | 설명 | 기본값 |
|---|---|---|
| `SECRET_KEY` | Flask 세션 서명 키. 지정하지 않으면 최초 실행 시 `.secret_key` 파일에 랜덤 값을 생성/저장합니다. | 자동 생성 |
| `ADMIN_PASSWORD` | 최초 실행 시 생성되는 관리자 계정의 비밀번호. 지정하지 않으면 무작위 생성 후 콘솔에 1회 출력. | 무작위 생성 |
| `FLASK_DEBUG` | `1`로 설정하면 디버그 모드로 실행됩니다(운영 환경에서는 사용 금지). | `0` |
| `FLASK_ENV` | `production`으로 설정하면 세션 쿠키에 `Secure` 플래그가 적용됩니다(HTTPS 필수). | 미설정 |

## 보안 관련 참고사항

- 비밀번호는 `werkzeug.security`의 `generate_password_hash`(salted hash)로 저장됩니다.
- 모든 상태 변경 요청(POST)에는 CSRF 토큰 검증이 적용됩니다.
- 로그인 5회 실패 시 5분간 계정이 잠깁니다.
- 세션 쿠키는 `HttpOnly`, `SameSite=Lax` 로 설정되며, `FLASK_ENV=production` + HTTPS 환경에서는 `Secure` 플래그가 추가로 적용됩니다.
- 모든 SQL 쿼리는 파라미터 바인딩을 사용하여 SQL Injection을 방지합니다.
- 응답에는 `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy` 등의 보안 헤더가 적용됩니다.
- 자세한 보안 점검 내역은 `secure_coding_checklist.csv`와 별도 제출한 보고서를 참고하세요.

## 프로젝트 구조

```
app.py                     # 서버 애플리케이션 (라우트, 소켓 이벤트, 보안 로직)
templates/                 # Jinja2 템플릿
secure_coding_checklist.csv  # 보안 점검 체크리스트
enviroments.yaml           # conda 환경 설정
```
