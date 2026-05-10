package mail

import (
	"userControl/config"
	"userControl/func/mail/send"
	"userControl/func/mail/html"
)

var CFG = &config.EmailConfig{}

func SendCaptcha(to, Captcha string){
	sender := sendMail.NewEmailSender(CFG)
	htmlContent := generateHtml.GenerateVerificationHTML(Captcha)
	sender.SendHTMLEmail([]string{to}, "【安全验证】您的验证码", htmlContent)
}