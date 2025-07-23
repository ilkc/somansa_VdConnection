package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/danieljoos/wincred"
	"golang.org/x/crypto/scrypt"
)

type VdConnection interface {
	InitConfig()
	Login()
	TwoFactorAuth()
	VdCon()
	Session()
}

type NurumLab struct {
	Id        string             `json:"id"`
	Password  string             `json:"password"`
	OtpSecret string             `json:"otp_secret"`
	Ctx       context.Context    `json:"-"`
	Cancel    context.CancelFunc `json:"-"`
}

type EncryptedConfig struct {
	EncryptedData string `json:"encrypted_data"`
	Salt          string `json:"salt"`
}

const (
	CredentialTarget = "vdConnection_encryption_key"
	AppName          = "vdConnection"
)

// Credential Manager에서 암호화 키 가져오기/저장하기
func getOrCreateEncryptionKey() ([]byte, error) {
	// 기존 키 확인
	cred, err := wincred.GetGenericCredential(CredentialTarget)
	if err == nil && len(cred.CredentialBlob) == 32 {
		fmt.Println("✅ 기존 암호화 키를 Credential Manager에서 가져왔습니다.")
		return cred.CredentialBlob, nil
	}

	// 새 키 생성
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("암호화 키 생성 실패: %v", err)
	}

	// Credential Manager에 저장
	newCred := wincred.NewGenericCredential(CredentialTarget)
	newCred.CredentialBlob = key
	newCred.UserName = AppName
	newCred.Comment = "vdConnection 설정 파일 암호화 키"

	if err := newCred.Write(); err != nil {
		return nil, fmt.Errorf("Credential Manager에 키 저장 실패: %v", err)
	}

	fmt.Println("🔑 새 암호화 키를 생성하여 Credential Manager에 저장했습니다.")
	return key, nil
}

// 데이터 암호화
func encryptData(data []byte, key []byte) (string, string, error) {
	// Salt 생성
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", fmt.Errorf("salt 생성 실패: %v", err)
	}

	// Key derivation
	derivedKey, err := scrypt.Key(key, salt, 32768, 8, 1, 32)
	if err != nil {
		return "", "", fmt.Errorf("키 유도 실패: %v", err)
	}

	// AES-GCM 암호화
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", "", fmt.Errorf("AES cipher 생성 실패: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", fmt.Errorf("GCM 생성 실패: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", fmt.Errorf("nonce 생성 실패: %v", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	return base64.StdEncoding.EncodeToString(ciphertext),
		base64.StdEncoding.EncodeToString(salt), nil
}

// 데이터 복호화
func decryptData(encryptedData string, saltStr string, key []byte) ([]byte, error) {
	// Base64 디코딩
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("암호화된 데이터 디코딩 실패: %v", err)
	}

	salt, err := base64.StdEncoding.DecodeString(saltStr)
	if err != nil {
		return nil, fmt.Errorf("salt 디코딩 실패: %v", err)
	}

	// Key derivation
	derivedKey, err := scrypt.Key(key, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("키 유도 실패: %v", err)
	}

	// AES-GCM 복호화
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("AES cipher 생성 실패: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM 생성 실패: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("암호화된 데이터가 너무 짧습니다")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("복호화 실패: %v", err)
	}

	return plaintext, nil
}

func Init(nurm *NurumLab) {
	// 암호화 키 가져오기/생성
	encKey, err := getOrCreateEncryptionKey()
	if err != nil {
		fmt.Printf("❌ 암호화 키 준비 실패: %v\n", err)
		return
	}

	// 기존 암호화된 설정 파일 확인
	file, err := os.Open("config.json")
	if err != nil {
		// 파일이 없으면 새로 생성
		fmt.Println("🔧 새로운 설정을 입력해주세요:")

		fmt.Printf("id : ")
		stdin := bufio.NewReader(os.Stdin)
		n, err := fmt.Scanln(&nurm.Id)
		if err != nil {
			fmt.Println(n, err)
			stdin.ReadString('\n')
		}

		fmt.Printf("password : ")
		n, err = fmt.Scanln(&nurm.Password)
		if err != nil {
			fmt.Println(n, err)
			stdin.ReadString('\n')
		}

		fmt.Printf("OTP Secret Key (OTP 앱에서 복사): ")
		n, err = fmt.Scanln(&nurm.OtpSecret)
		if err != nil {
			fmt.Println(n, err)
			stdin.ReadString('\n')
		}

		// 설정을 암호화하여 저장
		saveEncryptedConfig(nurm, encKey)
		return
	}
	defer file.Close()

	// 암호화된 설정 파일 로드
	var encConfig EncryptedConfig
	if err := json.NewDecoder(file).Decode(&encConfig); err != nil {
		fmt.Printf("❌ 암호화된 설정 파일 읽기 실패: %v\n", err)
		// 평문 파일일 가능성 확인
		file.Seek(0, 0)
		if err := json.NewDecoder(file).Decode(nurm); err == nil {
			fmt.Println("🔄 평문 설정 파일을 발견했습니다. 암호화하여 저장합니다...")
			saveEncryptedConfig(nurm, encKey)
			return
		}
		return
	}

	// 복호화
	decryptedData, err := decryptData(encConfig.EncryptedData, encConfig.Salt, encKey)
	if err != nil {
		fmt.Printf("❌ 설정 복호화 실패: %v\n", err)
		return
	}

	// JSON 디코딩
	if err := json.Unmarshal(decryptedData, nurm); err != nil {
		fmt.Printf("❌ 설정 JSON 디코딩 실패: %v\n", err)
		return
	}

	fmt.Println("✅ 암호화된 설정을 성공적으로 로드했습니다.")
}

// 암호화된 설정 저장
func saveEncryptedConfig(nurm *NurumLab, encKey []byte) {
	// JSON 인코딩
	jsonData, err := json.Marshal(nurm)
	if err != nil {
		fmt.Printf("❌ JSON 인코딩 실패: %v\n", err)
		return
	}

	// 데이터 암호화
	encryptedData, salt, err := encryptData(jsonData, encKey)
	if err != nil {
		fmt.Printf("❌ 데이터 암호화 실패: %v\n", err)
		return
	}

	// 암호화된 설정 구조체 생성
	encConfig := EncryptedConfig{
		EncryptedData: encryptedData,
		Salt:          salt,
	}

	// 파일에 저장
	configFile, err := os.Create("config.json")
	if err != nil {
		fmt.Printf("❌ config.json 파일 생성 실패: %v\n", err)
		return
	}
	defer configFile.Close()

	encoder := json.NewEncoder(configFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(encConfig); err != nil {
		fmt.Printf("❌ 암호화된 설정 저장 실패: %v\n", err)
		return
	}

	fmt.Println("🔒 설정이 암호화되어 저장되었습니다.")
}

func (nurm *NurumLab) InitConfig() {
	Init(nurm)
}

// 개선된 TOTP 코드 생성 함수
func (nurm *NurumLab) GenerateOTP() (string, error) {
	if nurm.OtpSecret == "" {
		return "", fmt.Errorf("OTP secret이 설정되지 않았습니다")
	}

	// 입력 secret 정리 (공백, 하이픈, 언더스코어 제거 및 대문자 변환)
	secret := strings.ToUpper(strings.ReplaceAll(
		strings.ReplaceAll(
			strings.ReplaceAll(nurm.OtpSecret, " ", ""),
			"-", ""),
		"_", ""))

	//fmt.Printf("🔍 처리된 OTP Secret: %s (길이: %d)\n", secret, len(secret))

	// Base32 패딩 추가 (필요한 경우)
	switch len(secret) % 8 {
	case 2:
		secret += "======"
	case 4:
		secret += "===="
	case 5:
		secret += "==="
	case 7:
		secret += "="
	}

	// Base32 디코딩 시도
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		// 표준 Base32가 실패하면 NoPadding 방식으로 시도
		fmt.Printf("⚠️ 표준 Base32 디코딩 실패, NoPadding 방식으로 재시도...\n")
		key, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(secret, "="))
		if err != nil {
			return "", fmt.Errorf("OTP secret 디코딩 실패: %v\n입력된 secret: %s\n처리된 secret: %s", err, nurm.OtpSecret, secret)
		}
	}

	fmt.Printf("✅ Base32 디코딩 성공, 키 길이: %d 바이트\n", len(key))

	// 현재 시간을 30초 단위로 계산
	timeStep := time.Now().Unix() / 30

	// 시간을 바이트 배열로 변환
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(timeStep))

	// HMAC-SHA1 해시 계산
	mac := hmac.New(sha1.New, key)
	mac.Write(timeBytes)
	hash := mac.Sum(nil)

	// Dynamic truncation
	offset := hash[len(hash)-1] & 0x0F
	code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7FFFFFFF

	// 6자리 코드로 변환
	otpCode := fmt.Sprintf("%06d", code%1000000)
	return otpCode, nil
}

// OTP Secret 유효성 검증 함수 (선택사항)
func ValidateOTPSecret(secret string) error {
	// 기본 정리
	cleaned := strings.ToUpper(strings.ReplaceAll(
		strings.ReplaceAll(
			strings.ReplaceAll(secret, " ", ""),
			"-", ""),
		"_", ""))

	// Base32 문자 검증 (A-Z, 2-7만 허용)
	for _, char := range cleaned {
		if !((char >= 'A' && char <= 'Z') || (char >= '2' && char <= '7')) {
			return fmt.Errorf("유효하지 않은 Base32 문자: %c", char)
		}
	}

	// 길이 검증 (일반적으로 16, 26, 32자)
	if len(cleaned) < 16 {
		return fmt.Errorf("OTP secret이 너무 짧습니다 (최소 16자): %d", len(cleaned))
	}

	return nil
}

func (nurm *NurumLab) Session() {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", false),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.WindowSize(1200, 800),
	)
	allocCtx, _ := chromedp.NewExecAllocator(context.Background(), opts...)

	nurm.Ctx, nurm.Cancel = chromedp.NewContext(allocCtx)
	nurm.Ctx, nurm.Cancel = context.WithTimeout(nurm.Ctx, 60*time.Second)
}

func (nurm *NurumLab) Close() {
	if nurm.Cancel != nil {
		nurm.Cancel()
		nurm.Cancel = nil
	}
}

func (nurm *NurumLab) Login() {
	var vdurl string = "http://nurum.lab.somansa.com/portal/auth/login"

	fmt.Printf("🔐 로그인 시작: %s\n", vdurl)

	err := chromedp.Run(nurm.Ctx,
		// 페이지 이동
		chromedp.Navigate(vdurl),
		chromedp.WaitVisible(`input[autocomplete="username"]`, chromedp.ByQuery),

		chromedp.SendKeys(`input[autocomplete="username"]`, nurm.Id, chromedp.ByQuery),

		chromedp.SendKeys(`input[autocomplete="current-password"]`, nurm.Password, chromedp.ByQuery),

		// 잠시 대기 (확인용)
		chromedp.Sleep(1*time.Second),
		chromedp.ActionFunc(func(ctx context.Context) error {
			selector := `button[type="submit"]`
			err := chromedp.Click(selector, chromedp.ByQuery).Do(ctx)
			if err == nil {
				fmt.Printf("✅ 로그인 버튼 클릭 성공: %s\n", selector)
				return nil
			}
			// 엔터키로 시도
			return chromedp.SendKeys(`input[autocomplete="current-password"]`, "\n", chromedp.ByQuery).Do(ctx)
		}),
	)
	if err != nil {
		fmt.Printf("❌로그인 실패: %v\n", err)
	}
}

func (nurm *NurumLab) TwoFactorAuth() {
	fmt.Printf("🔑 OTP 인증 확인 중...\n")

	// 2FA 입력 필드가 나타날 때까지 대기
	err := chromedp.Run(nurm.Ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			// OTP 입력 필드 선택자 (제공된 HTML 요소 기반)
			selectors := []string{
				`input[id="otpNumber"]`,
				`input[placeholder="인증코드 입력"]`,
				`input[name="code"]`,
				`input[name="token"]`,
				`input[name="otp"]`,
				`input[name="twoFactorCode"]`,
				`input[placeholder*="인증"]`,
				`input[placeholder*="코드"]`,
				`input[type="text"][maxlength="6"]`,
			}

			var foundSelector string
			for _, selector := range selectors {
				err := chromedp.WaitVisible(selector, chromedp.ByQuery).Do(ctx)
				if err == nil {
					foundSelector = selector
					fmt.Printf("✅ 2FA 입력 필드 발견: %s\n", selector)
					break
				}
			}

			if foundSelector == "" {
				fmt.Printf("ℹ️ OTP 인증이 필요하지 않습니다.\n")
				return nil
			}

			fmt.Printf("✅ OTP 입력 필드 발견: %s\n", foundSelector)
			return nil
		}),
	)

	if err != nil {
		fmt.Printf("❌ OTP 필드 확인 실패: %v\n", err)
		return
	}

	// OTP 코드 자동 생성 및 입력
	otpCode, err := nurm.GenerateOTP()
	if err != nil {
		fmt.Printf("❌ OTP 생성 실패: %v\n", err)
		return
	}

	fmt.Printf("🔑 자동 생성된 OTP 코드: %s\n", otpCode)

	err = chromedp.Run(nurm.Ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			// OTP 입력 필드 선택자
			otpSelector := `input[id="otpNumber"]`

			if err := chromedp.WaitVisible(otpSelector, chromedp.ByQuery).Do(ctx); err != nil {
				return err
			}

			// OTP 코드 입력
			if err := chromedp.SendKeys(otpSelector, otpCode, chromedp.ByQuery).Do(ctx); err != nil {
				return err
			}

			// 확인 버튼 클릭
			confirmSelector := `button[type="submit"].ant-btn.ant-btn-primary.ant-btn-lg.ant-btn-block`
			if err := chromedp.Click(confirmSelector, chromedp.ByQuery).Do(ctx); err != nil {
				// 일반 submit 버튼으로 시도
				if err := chromedp.Click(`button[type="submit"]`, chromedp.ByQuery).Do(ctx); err != nil {
					return err
				}
			}

			fmt.Printf("✅ OTP 인증 완료\n")
			time.Sleep(1 * time.Second) // 인증 처리 대기
			return nil
		}),
	)

	if err != nil {
		fmt.Printf("❌ OTP 인증 실패: %v\n", err)
	}
}

func (nurm *NurumLab) VdCon() {
	fmt.Printf("🔗 vd 접속 시작\n")
	err := chromedp.Run(nurm.Ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			selector := `button[class*="sc-ezbkAF"]`
			if err := chromedp.WaitVisible(selector, chromedp.ByQuery).Do(ctx); err != nil {
				return err
			}
			time.Sleep(2 * time.Second)

			if err := chromedp.Click(selector, chromedp.ByQuery).Do(ctx); err != nil {
				return err
			}
			fmt.Printf("🌐 vd 접속 성공: %s\n", selector)
			return nil
		}),
	)
	if err != nil {
		fmt.Printf("❌vd 연결 실패: %v\n", err)
	}
}

func main() {
	fmt.Printf("start vdi\n")
	var nurm = &NurumLab{}
	nurm.InitConfig()
	nurm.Session()
	defer nurm.Close()
	nurm.Login()
	nurm.TwoFactorAuth()
	nurm.VdCon()
}
