# vdConnection

보안 강화된 VDI(Virtual Desktop Infrastructure) 자동 연결 도구

Nurum Lab의 VDI에 자동으로 로그인하고 연결하는 Go 기반 도구입니다. AES-256 암호화와 Windows Credential Manager를 사용하여 사용자 인증 정보를 안전하게 보호합니다.

## 🔒 보안 기능

- **AES-256-GCM 암호화**: 사용자 인증 정보를 AES-256-GCM 알고리즘으로 암호화
- **Windows Credential Manager 연동**: 암호화 키를 시스템 레벨에서 안전하게 관리
- **Salt 기반 키 유도**: scrypt를 사용한 안전한 키 유도 함수
- **데이터 무결성 검증**: GCM 모드로 데이터 변조 감지
- **기존 평문 파일 자동 변환**: 기존 평문 설정을 자동으로 암호화

## 📋 기능

- VDI 포털 자동 로그인
- TOTP(Time-based OTP) 자동 생성 및 입력
- 2단계 인증 자동 처리
- VDI 데스크톱 자동 연결
- 암호화된 설정 파일 관리
- Interface 패턴으로 확장 가능한 구조

## 🛠️ 요구사항

### 필수 소프트웨어
- **OS**: Windows (Credential Manager 사용)
- **Go**: 1.21 이상
- **Chrome/Chromium**: 브라우저 자동화용

### 의존성 패키지
```bash
go mod init vdConnection
go get github.com/chromedp/chromedp
go get github.com/danieljoos/wincred
go get golang.org/x/crypto/scrypt
```

## 🚀 사용법

### 1. 초기 설정
프로그램을 처음 실행하면 설정 정보를 입력하라는 프롬프트가 나타납니다:

```bash
./vdConnection.exe
```

다음 정보를 입력하세요:
- **ID**: VDI 포털 로그인 ID
- **Password**: VDI 포털 로그인 비밀번호  
- **OTP Secret Key**: TOTP 앱에서 제공하는 시크릿 키

### 2. 암호화된 설정 파일 형식
입력한 정보는 암호화되어 `config.json` 파일에 저장됩니다:
```json
{
  "encrypted_data": "base64로 인코딩된 암호화된 데이터",
  "salt": "base64로 인코딩된 Salt"
}
```

## 🔧 주요 구성 요소

### NurumLab 구조체
```go
type NurumLab struct {
    Id        string             `json:"id"`
    Password  string             `json:"password"`
    OtpSecret string             `json:"otp_secret"`
    Ctx       context.Context    `json:"-"`
    Cancel    context.CancelFunc `json:"-"`
}
```

### EncryptedConfig 구조체
```go
type EncryptedConfig struct {
    EncryptedData string `json:"encrypted_data"`
    Salt          string `json:"salt"`
}
```

### 주요 메서드
- `InitConfig()`: 암호화된 설정 파일 초기화
- `Session()`: Chrome 브라우저 세션 생성
- `Login()`: 자동 로그인 수행
- `TwoFactorAuth()`: TOTP 2단계 인증 처리
- `GenerateOTP()`: TOTP 코드 자동 생성
- `VdCon()`: VDI 연결 수행
- `Close()`: 리소스 정리

### 보안 함수들
- `getOrCreateEncryptionKey()`: Credential Manager에서 암호화 키 관리
- `encryptData()`: AES-256-GCM 암호화
- `decryptData()`: AES-256-GCM 복호화
- `saveEncryptedConfig()`: 암호화된 설정 저장

## 🔐 보안 아키텍처

### 암호화 프로세스
1. **키 생성**: 32바이트 랜덤 암호화 키 생성
2. **키 저장**: Windows Credential Manager에 안전하게 저장
3. **Salt 생성**: 각 암호화마다 16바이트 랜덤 Salt 생성
4. **키 유도**: scrypt(키, Salt, N=32768, r=8, p=1)로 유도키 생성
5. **암호화**: AES-256-GCM으로 데이터 암호화
6. **저장**: Base64로 인코딩하여 JSON 파일에 저장

### Credential Manager 정보
- **Target**: `vdConnection_encryption_key`
- **UserName**: `vdConnection`
- **Comment**: `vdConnection 설정 파일 암호화 키`

### TOTP 구현
- **알고리즘**: HMAC-SHA1
- **시간 단위**: 30초
- **코드 길이**: 6자리
- **Base32 디코딩**: 표준 및 NoPadding 방식 지원

## ⚙️ 브라우저 옵션
프로그램은 다음 Chrome 옵션으로 실행됩니다:
- **헤드리스 모드**: 기본 활성화
- **창 크기**: 1200x800
- **타임아웃**: 60초
- **GPU 설정**: 비활성화 안 함
- **샌드박스**: 비활성화

## 🛡️ 보안 고려사항

### 강점
- ✅ 설정 파일이 암호화되어 평문 노출 방지
- ✅ 암호화 키가 Windows 보안 저장소에 안전하게 보관
- ✅ 각 저장마다 다른 Salt 사용으로 무지개 테이블 공격 방지
- ✅ GCM 모드로 데이터 무결성 검증
- ✅ 기존 평문 파일 자동 암호화 변환

### 주의사항
- ⚠️ Windows Credential Manager에 접근 권한이 있는 사용자는 키에 접근 가능
- ⚠️ 프로그램 실행 중 메모리에 복호화된 데이터가 존재
- ⚠️ 시스템 관리자 권한으로 실행 시 더 높은 보안 위험


## 🐛 문제 해결

### 일반적인 문제

**Q: "암호화 키 준비 실패" 에러가 발생합니다**
A: Windows Credential Manager 접근 권한을 확인하세요. 관리자 권한으로 실행해보세요.

**Q: OTP 코드가 맞지 않습니다**
A: 
- 시스템 시간이 정확한지 확인하세요
- OTP Secret Key가 올바르게 입력되었는지 확인하세요
- 공백, 하이픈, 언더스코어는 자동으로 제거됩니다

**Q: 브라우저 연결이 실패합니다**
A: Chrome/Chromium이 설치되어 있는지 확인하고, 방화벽 설정을 점검하세요.

**Q: Chrome 브라우저를 찾을 수 없음**
A: Chrome 또는 Chromium이 설치되어 있는지 확인하고, PATH 환경변수를 점검하세요.

**Q: VDI 연결 실패**
A: 페이지 로딩 시간 확인 및 웹사이트 UI 변경 여부를 확인하세요.

### 디버깅
- Headless 모드를 비활성화하여 브라우저 동작을 직접 확인할 수 있습니다:
```go
chromedp.Flag("headless", false),
```

## 📝 로그 메시지

프로그램 실행 시 다음과 같은 로그 메시지를 확인할 수 있습니다:

### 보안 관련
- 🔑 새 암호화 키 생성
- ✅ 기존 암호화 키 로드
- 🔒 설정 암호화 저장 완료
- 🔄 평문 파일 자동 변환

### 인증 관련
- 🔐 로그인 시작
- ✅ 로그인 버튼 클릭 성공
- 🔑 OTP 인증 확인 중
- 🔑 자동 생성된 OTP 코드
- ✅ OTP 인증 완료

### 연결 관련
- 🔗 vd 접속 시작
- 🌐 vd 접속 성공
- ❌ 오류 메시지 (실패 시)

## 📦 빌드 및 배포

### 빌드
```bash
go build -o vdConnection.exe vdConnection.go
```

### 실행
```bash
./vdConnection.exe
```

## 📄 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다.

## 🤝 기여

버그 리포트나 기능 제안은 이슈로 등록해주세요.

---

**⚠️ 보안 공지**: 이 도구는 개인 사용 목적으로 제작되었습니다. 프로덕션 환경에서 사용하기 전에 충분한 보안 검토를 수행하세요.