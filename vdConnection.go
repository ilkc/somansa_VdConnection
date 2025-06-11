package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/chromedp/chromedp"
)

type VdConnection interface {
	InitConfig()
	Login()
	VdCon()
	Session()
}

type NurumLab struct {
	Id       string `json:"id"`
	Password string `json:"password"`
	Ctx      context.Context
	Cancel   context.CancelFunc
}

func Init(nurm *NurumLab) {
	file, err := os.Open("config.json")
	if err != nil {
		fmt.Printf("id : ")
		stdin := bufio.NewReader(os.Stdin)
		n, err := fmt.Scanln(&nurm.Id)
		if err != nil {
			fmt.Println(n, err)
			stdin.ReadString('\n')
		}
		fmt.Printf("passowrd : ")
		n, err = fmt.Scanln(&nurm.Password)
		if err != nil {
			fmt.Println(n, err)
			stdin.ReadString('\n')
		}
		configFile, _ := os.Create("config.json")
		defer configFile.Close()
		encoder := json.NewEncoder(configFile)
		encoder.SetIndent("", "  ")
		encoder.Encode(nurm)
		fmt.Println("config.json 파일이 생성되었습니다.")
	}
	defer file.Close()
	json.NewDecoder(file).Decode(nurm)
}

func (nurm *NurumLab) InitConfig() {
	Init(nurm)
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
	nurm.Ctx, nurm.Cancel = context.WithTimeout(nurm.Ctx, 20*time.Second)
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
		fmt.Println("❌로그인 실패: %w", err)
	}

}

func (nurm *NurumLab) VdCon() {
	fmt.Printf("🔗 vd 접속 시작\n")
	err := chromedp.Run(nurm.Ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			selector := `button[class*="Xaubw"]`
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
		fmt.Println("❌vd 연결 실패: %w", err)
	}
}

func main() {
	fmt.Printf("start vdi\n")
	var nurm = &NurumLab{}
	nurm.InitConfig()
	nurm.Session()
	defer nurm.Close()
	nurm.Login()
	nurm.VdCon()
}
