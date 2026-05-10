package generateHtml

import (
	"fmt"
	"html"
)

func GenerateVerificationHTML(code string) string {
	if code == "" {
		code = "N/A"
	} else {
		code = html.EscapeString(code)
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>验证码提示</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #87CEEB 0%%, #4B0082 100%%);
            background-attachment: fixed;
            padding: 20px;
            min-height: 100vh;
        }
        
        .container {
            max-width: 500px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.3);
        }
        
        .header {
            background: linear-gradient(135deg, #87CEEB 0%%, #4B0082 100%%);
            color: white;
            padding: 30px 20px;
            text-align: center;
            position: relative;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="20" cy="20" r="2" fill="rgba(255,255,255,0.1)"/><circle cx="80" cy="40" r="1.5" fill="rgba(255,255,255,0.1)"/><circle cx="40" cy="80" r="1" fill="rgba(255,255,255,0.1)"/></svg>');
            opacity: 0.3;
        }
        
        .header h1 {
            font-size: 28px;
            font-weight: 600;
            margin-bottom: 10px;
            position: relative;
            z-index: 1;
        }
        
        .header p {
            font-size: 16px;
            opacity: 0.9;
            position: relative;
            z-index: 1;
        }
        
        .content {
            padding: 40px 30px;
        }
        
        .verification-box {
            background: linear-gradient(135deg, #f0f8ff 0%%, #e6f3ff 100%%);
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 25px;
            border: 2px solid #4a90e2;
            box-shadow: 0 5px 15px rgba(74, 144, 226, 0.1);
        }
        
        .verification-title {
            color: #2c3e50;
            font-size: 22px;
            margin-bottom: 20px;
            font-weight: 600;
            text-align: center;
            position: relative;
        }
        
        .verification-title::after {
            content: '';
            display: block;
            width: 50px;
            height: 3px;
            background: linear-gradient(135deg, #87CEEB 0%%, #4B0082 100%%);
            margin: 10px auto 0;
            border-radius: 2px;
        }
        
        .verification-item {
            margin-bottom: 18px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 15px;
            background: rgba(255, 255, 255, 0.7);
            border-radius: 8px;
            transition: transform 0.2s ease;
        }
        
        .verification-item:hover {
            transform: translateX(5px);
        }
        
        .verification-item:last-child {
            margin-bottom: 0;
        }
        
        .label {
            color: #555;
            font-size: 16px;
            font-weight: 500;
        }
        
        .value {
            font-size: 20px;
            font-weight: 700;
            letter-spacing: 2px;
            text-transform: uppercase;
        }
        
        .code-value {
            background: linear-gradient(135deg, #87CEEB 0%%, #4B0082 100%%);
            color: white;
            padding: 10px 20px;
            border-radius: 25px;
            font-family: 'Courier New', monospace;
            box-shadow: 0 4px 15px rgba(139, 0, 130, 0.3);
            position: relative;
            overflow: hidden;
        }
        
        .code-value::before {
            content: '';
            position: absolute;
            top: -50%%;
            left: -50%%;
            width: 200%%;
            height: 200%%;
            background: linear-gradient(45deg, transparent, rgba(255,255,255,0.2), transparent);
            transform: rotate(45deg);
            transition: all 0.5s ease;
        }
        
        .code-value:hover::before {
            transform: rotate(45deg) translate(20%%, 20%%);
        }
        
        .time-value {
            color: #e74c3c;
            background: rgba(231, 76, 60, 0.1);
            padding: 8px 15px;
            border-radius: 20px;
            border: 1px solid #e74c3c;
        }
        
        .note {
            margin-top: 25px;
            padding: 15px;
            background: rgba(254, 240, 240, 0.5);
            border-left: 4px solid #e74c3c;
            border-radius: 0 8px 8px 0;
            color: #7f8c8d;
            font-size: 14px;
            line-height: 1.6;
        }
        
        .security-tip {
            margin-top: 15px;
            padding: 10px;
            background: rgba(236, 240, 241, 0.5);
            border-radius: 8px;
            font-size: 13px;
            color: #95a5a6;
            text-align: center;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #7f8c8d;
            font-size: 12px;
            background: rgba(248, 249, 250, 0.8);
            border-top: 1px solid #eee;
        }
        
        @media (max-width: 600px) {
            .container {
                margin: 10px;
            }
            
            .content {
                padding: 25px 20px;
            }
            
            .header h1 {
                font-size: 24px;
            }
            
            .verification-title {
                font-size: 20px;
            }
            
            .value {
                font-size: 18px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>安全验证</h1>
            <p>您的验证码已生成</p>
        </div>
        
        <div class="content">
            <div class="verification-box">
                <h2 class="verification-title">验证码信息</h2>
                
				<div class="verification-item">
					<span class="label">您的验证码：</span>
					<span class="value code-value">%s</span>
				</div>
                
                <div class="verification-item">
                    <span class="label">有效期：</span>
                    <span class="value time-value">5分钟</span>
                </div>
                
                <p class="note">
                    请在5分钟内完成验证，验证码过期后将失效。请勿将验证码泄露给他人。
                </p>

            </div>

            <div class="footer">
                <p>此邮件由系统自动发送，请勿回复</p>
                <p>© 安全验证服务. 保护账户安全</p>
            </div>
        </div>
    </div>
</body>
</html>`, code)
}
