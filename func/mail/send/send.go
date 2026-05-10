package sendMail

import (
	"fmt"
	"strings"
	"net/smtp"
	"crypto/tls"

	"userControl/config"
)

type EmailSender struct {
	cfg *config.EmailConfig
}

func NewEmailSender(cfg *config.EmailConfig) *EmailSender {
	return &EmailSender{cfg: cfg}
}

func (c *EmailSender) SendHTMLEmail(to []string, subject, htmlBody string) error {
	emailBody := fmt.Sprintf(
		"From: %s\r\n"+
			"To: %s\r\n"+
			"Subject: %s\r\n"+
			"Content-Type: text/html; charset=UTF-8\r\n"+
			"\r\n"+
			"%s",
		c.cfg.From,
		strings.Join(to, ","),
		subject,
		htmlBody,
	)

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", c.cfg.Host, c.cfg.Port), &tls.Config{
		ServerName: c.cfg.Host,
	})
	if err != nil {
		return fmt.Errorf("连接SMTP服务器失败: %v", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, c.cfg.Host)
	if err != nil {
		return fmt.Errorf("创建SMTP客户端失败: %v", err)
	}
	defer client.Quit()

	auth := smtp.PlainAuth("", c.cfg.From, c.cfg.Password, c.cfg.Host)
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("SMTP认证失败: %v", err)
	}

	if err := client.Mail(c.cfg.From); err != nil {
		return fmt.Errorf("设置发件人失败: %v", err)
	}

	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("设置收件人失败: %v", err)
		}
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("获取数据写入器失败: %v", err)
	}
	defer wc.Close()

	_, err = wc.Write([]byte(emailBody))
	if err != nil {
		return fmt.Errorf("写入邮件内容失败: %v", err)
	}

	return nil
}