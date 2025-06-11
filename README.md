# NurumLab VDI 자동 접속 도구

Nurum Lab의 VDI(Virtual Desktop Infrastructure)에 자동으로 로그인하고 연결하는 Go 기반 도구입니다.

interface를 사용하여 코드 수정 추가를 편하게 만들었습니다.

## 📋 기능

- 자동 로그인 처리
- VDI 세션 자동 연결
- 설정 파일 자동 생성 및 관리
- Headless Chrome을 이용한 브라우저 자동화

## 🛠️ 설치 요구사항

### 필수 소프트웨어
- Go 1.18 이상
- Google Chrome 또는 Chromium 브라우저

### 의존성 패키지
```bash
go mod init nurum-vdi
go get github.com/chromedp/chromedp
```
## 🚀 사용법
### 1. 초기 설정
프로그램을 처음 실행하면 다음 정보를 입력하라는 메시지가 표시됩니다:
- **ID**: Nurum Lab 계정 ID
- **Password**: Nurum Lab 계정 비밀번호

입력한 정보는 `config.json` 파일에 자동으로 저장됩니다.

### 2. 설정 파일 형식
`config.json` 파일은 다음과 같은 형식으로 생성됩니다:
```json
{
  "id": "your_username",
  "password": "your_password"
}
```

## 🔧 주요 구성 요소

### NurumLab 구조체
```go
type NurumLab struct {
    Id       string `json:"id"`
    Password string `json:"password"`
    Ctx      context.Context
    Cancel   context.CancelFunc
}
```

### 주요 메서드
- `InitConfig()`: 설정 파일 초기화
- `Session()`: Chrome 브라우저 세션 생성
- `Login()`: 자동 로그인 수행
- `VdCon()`: VDI 연결 수행
- `Close()`: 리소스 정리

## ⚙️ 브라우저 옵션
프로그램은 다음 Chrome 옵션으로 실행됩니다:
- Headless 모드 활성화
- GPU 비활성화 안 함
- 개발자 공유 메모리 사용 비활성화
- 샌드박스 비활성화
- 창 크기: 1200x800
- 타임아웃: 20초

## 🔒 보안 고려사항
- `config.json` 파일에는 평문으로 비밀번호가 저장됩니다
- 공개 저장소에 `config.json`을 업로드하지 마세요


## 🐛 문제 해결

### 일반적인 문제
1. **Chrome 브라우저를 찾을 수 없음**
   - Chrome 또는 Chromium이 설치되어 있는지 확인
   - PATH 환경변수에 Chrome이 등록되어 있는지 확인

2. **로그인 실패**
   - 네트워크 연결 상태 확인
   - ID/비밀번호 정확성 확인
   - VPN 연결 상태 확인 (필요한 경우)

3. **VDI 연결 실패**
   - 페이지 로딩 시간 확인
   - 웹사이트 UI 변경 여부 확인

### 디버깅
- Headless 모드를 비활성화하여 브라우저 동작을 직접 확인할 수 있습니다:
```go
chromedp.Flag("headless", false),
```

## 📝 로그 메시지

프로그램 실행 시 다음과 같은 로그 메시지를 확인할 수 있습니다:
- 🔐 로그인 시작
- ✅ 로그인 버튼 클릭 성공
- 🔗 vd 접속 시작
- 🌐 vd 접속 성공
- ❌ 오류 메시지 (실패 시)



**주의**: 이 도구는 자동화된 접근을 위한 것이므로, 해당 시스템의 이용 약관을 준수하여 사용하시기 바랍니다.