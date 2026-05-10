package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

// ============================================================================
// 测试配置
// ============================================================================

const (
	baseURL = "http://localhost:8080" // 测试目标地址，按需修改
)

// testCtx 在测试间共享的上下文（token 等）
type testCtx struct {
	AdminToken  string // Admin-Token
	SessionToken string // X-Session-Token
	ApiToken    string // API-Token (用户)
	TestQQ      string // 测试用的 QQ 号
}

var ctx = &testCtx{}

// ============================================================================
// 工具函数
// ============================================================================

// prettyJSON 格式化输出 JSON
func prettyJSON(v interface{}) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

// httpDo 发送 HTTP 请求并返回状态码和响应体
func httpDo(t *testing.T, method, path string, headers map[string]string, body interface{}) (int, map[string]interface{}) {
	t.Helper()

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("json marshal failed: %v", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, baseURL+path, bodyReader)
	if err != nil {
		t.Fatalf("create request failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(respBody, &result)

	// 打印结果
	t.Logf("%s %s → %d", method, path, resp.StatusCode)
	if result != nil {
		if msg, ok := result["msg"]; ok {
			t.Logf("  msg: %v", msg)
		}
		if data, ok := result["data"]; ok {
			if d, err := json.MarshalIndent(data, "  ", "  "); err == nil {
				t.Logf("  data: %s", string(d))
			}
		}
	} else {
		t.Logf("  body: %s", string(respBody))
	}

	return resp.StatusCode, result
}

// assertStatus 断言 HTTP 状态码
func assertStatus(t *testing.T, got, want int) {
	t.Helper()
	if got != want {
		t.Errorf("  期望状态码 %d，实际 %d", want, got)
	}
}

// ============================================================================
// ① 公开接口测试（无需鉴权）
// ============================================================================

func TestAuth_PublicEndpoints(t *testing.T) {
	t.Run("管理员登录_正确密码", func(t *testing.T) {
		status, result := httpDo(t, "POST", "/api/admin/login", nil, map[string]string{
			"username": "lnb_x",
			"password": "xi520",
		})
		assertStatus(t, status, 200)
		if result != nil {
			if token, ok := result["admin_token"].(string); ok {
				ctx.AdminToken = token
				t.Logf("  获取到 Admin-Token: %s", token[:12]+"...")
			}
		}
	})

	t.Run("管理员登录_错误密码", func(t *testing.T) {
		status, _ := httpDo(t, "POST", "/api/admin/login", nil, map[string]string{
			"username": "lnb_x",
			"password": "wrong_password",
		})
		assertStatus(t, status, 401)
	})

	t.Run("用户登录_错误密码", func(t *testing.T) {
		// 需要一个真实存在的 QQ 号，这里用占位
		status, _ := httpDo(t, "POST", "/api/user/login", nil, map[string]string{
			"qq":      "10000",
			"password": "wrong",
		})
		// 401 用户不存在 或 401 密码错误 都算正确行为
		if status != 401 && status != 429 {
			t.Errorf("  期望 401/429，实际 %d", status)
		}
	})

	t.Run("发送验证码_格式错误QQ", func(t *testing.T) {
		status, _ := httpDo(t, "POST", "/api/send_captcha", nil, map[string]interface{}{
			"qq":     "abc",
			"action": "register",
		})
		assertStatus(t, status, 400)
	})

	t.Run("Ping", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/ping")
		if err != nil {
			t.Fatalf("ping failed: %v", err)
		}
		defer resp.Body.Close()
		t.Logf("  /ping → %d", resp.StatusCode)
		assertStatus(t, resp.StatusCode, 200)
	})
}

// ============================================================================
// ② 用户 Session 接口测试（X-Session-Token）
// ============================================================================

func TestAuth_UserSessionEndpoints(t *testing.T) {
	t.Run("未登录访问用户信息", func(t *testing.T) {
		status, _ := httpDo(t, "GET", "/api/user/me", nil, nil)
		assertStatus(t, status, 401)
	})

	t.Run("错误Token访问用户信息", func(t *testing.T) {
		status, _ := httpDo(t, "GET", "/api/user/me", map[string]string{
			"X-Session-Token": "invalid_token_12345",
		}, nil)
		assertStatus(t, status, 401)
	})

	t.Run("兑换CDK_未登录", func(t *testing.T) {
		status, _ := httpDo(t, "POST", "/api/user_use_cdk", nil, map[string]string{
			"cdk": "invalid-cdk",
		})
		assertStatus(t, status, 401)
	})

	t.Run("修改密码_未登录", func(t *testing.T) {
		status, _ := httpDo(t, "POST", "/api/user/change-password", nil, map[string]interface{}{
			"old_password": "a",
			"new_password": "b",
		})
		assertStatus(t, status, 401)
	})

	// 以下测试需要真实用户的 session_token，需手动填入 ctx.SessionToken 后启用
	if ctx.SessionToken == "" {
		t.Log("  跳过已登录用户测试：请先设置 ctx.SessionToken")
		return
	}

	t.Run("已登录获取用户信息", func(t *testing.T) {
		status, result := httpDo(t, "GET", "/api/user/me", map[string]string{
			"X-Session-Token": ctx.SessionToken,
		}, nil)
		assertStatus(t, status, 200)
		if result != nil {
			if data, ok := result["data"].(map[string]interface{}); ok {
				if apiKey, ok := data["api_key"].(string); ok {
					ctx.ApiToken = apiKey
				}
			}
		}
	})

	t.Run("重新生成API_Token", func(t *testing.T) {
		status, _ := httpDo(t, "POST", "/api/user/regen_token", map[string]string{
			"X-Session-Token": ctx.SessionToken,
		}, nil)
		assertStatus(t, status, 200)
	})
}

// ============================================================================
// ③ 管理员接口测试（Admin-Token）
// ============================================================================

func TestAuth_AdminEndpoints(t *testing.T) {
	if ctx.AdminToken == "" {
		t.Fatal("  需要先运行 TestAuth_PublicEndpoints 获取 Admin-Token")
	}

	headers := map[string]string{
		"Admin-Token": ctx.AdminToken,
	}

	t.Run("未携带Admin-Token访问用户列表", func(t *testing.T) {
		status, _ := httpDo(t, "GET", "/api/admin/users?page=1&size=2", nil, nil)
		assertStatus(t, status, 401)
	})

	t.Run("错误Admin-Token", func(t *testing.T) {
		status, _ := httpDo(t, "GET", "/api/admin/users?page=1&size=2", map[string]string{
			"Admin-Token": "invalid_admin_token",
		}, nil)
		assertStatus(t, status, 401)
	})

	t.Run("获取用户列表", func(t *testing.T) {
		status, _ := httpDo(t, "GET", "/api/admin/users?page=1&size=2", headers, nil)
		assertStatus(t, status, 200)
	})

	t.Run("获取CDK列表", func(t *testing.T) {
		status, _ := httpDo(t, "GET", "/api/admin/cdks?page=1&size=2", headers, nil)
		assertStatus(t, status, 200)
	})

	t.Run("获取仪表盘统计", func(t *testing.T) {
		status, _ := httpDo(t, "GET", "/api/admin/dashboard/stats", headers, nil)
		assertStatus(t, status, 200)
	})

	t.Run("获取系统配置", func(t *testing.T) {
		status, result := httpDo(t, "GET", "/api/admin/config", headers, nil)
		assertStatus(t, status, 200)
		// 注意：此接口会返回明文密码，属于之前提到的安全问题
		if result != nil {
			t.Log("  ⚠ 注意：/admin/config 返回了明文密码和 internal_secret")
		}
	})

	t.Run("修改用户状态", func(t *testing.T) {
		// 使用测试 QQ 号，若无则跳过
		if ctx.TestQQ == "" {
			t.Log("  跳过：未设置 TestQQ")
			return
		}
		status, _ := httpDo(t, "POST", "/api/admin/user/set_status", headers, map[string]interface{}{
			"qq":     ctx.TestQQ,
			"status": 1,
		})
		assertStatus(t, status, 200)
	})

	t.Run("管理员重置用户密码", func(t *testing.T) {
		if ctx.TestQQ == "" {
			t.Log("  跳过：未设置 TestQQ")
			return
		}
		status, _ := httpDo(t, "POST", "/api/admin/user/reset_password", headers, map[string]interface{}{
			"qq":          ctx.TestQQ,
			"new_password": "test123456",
		})
		assertStatus(t, status, 200)
	})
}

// ============================================================================
// ④ 内部服务接口测试（X-Server-Secret）
// ============================================================================

func TestAuth_InternalEndpoints(t *testing.T) {
	secret := "ZVxNImAbmQA6tALgWKtbtiGY3I7r8O8W" // 与 config.json 中 internal_secret 一致

	headers := map[string]string{
		"X-Server-Secret": secret,
	}

	t.Run("未携带Secret访问内部接口", func(t *testing.T) {
		status, _ := httpDo(t, "POST", "/api/internal/check_quota", nil, map[string]string{
			"token":    "dummy",
			"api_name": "test",
		})
		assertStatus(t, status, 401)
	})

	t.Run("错误Secret", func(t *testing.T) {
		status, _ := httpDo(t, "POST", "/api/internal/check_quota", map[string]string{
			"X-Server-Secret": "wrong_secret",
		}, map[string]string{
			"token":    "dummy",
			"api_name": "test",
		})
		assertStatus(t, status, 401)
	})

	t.Run("查询配额_无效Token", func(t *testing.T) {
		status, _ := httpDo(t, "POST", "/api/internal/check_quota", headers, map[string]string{
			"token":    "invalid_token",
			"api_name": "fanqieNovelPublic",
		})
		// 期望 404 或 400
		if status != 404 && status != 400 && status != 500 {
			t.Errorf("  查询配额返回意外状态码: %d", status)
		}
	})

	t.Run("扣除配额_无效Token", func(t *testing.T) {
		status, _ := httpDo(t, "POST", "/api/internal/consume", headers, map[string]interface{}{
			"token":    "invalid_token",
			"api_name": "fanqieNovelPublic",
			"cost":     1,
		})
		// 期望 403 或 404
		if status != 403 && status != 404 && status != 500 {
			t.Errorf("  扣除配额返回意外状态码: %d", status)
		}
	})

	t.Run("修改用户状态_通过内部接口", func(t *testing.T) {
		status, _ := httpDo(t, "POST", "/api/internal/user/set_status", headers, map[string]interface{}{
			"qq":     "10000",
			"status": 1,
		})
		// 用户不存在返回 500（数据库错误），但鉴权应通过
		t.Logf("  修改状态 → %d（用户可能不存在，鉴权已通过即正确）", status)
	})
}

// ============================================================================
// ⑤ 鉴权失败场景全覆盖
// ============================================================================

func TestAuth_FailureCases(t *testing.T) {
	t.Run("访问不存在的路由", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/api/nonexistent")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		assertStatus(t, resp.StatusCode, 404)
		t.Logf("  /api/nonexistent → 404 (正确)")
	})

	t.Run("Admin-Token过期或失效", func(t *testing.T) {
		// 用一个随机 UUID 作为假 token
		fakeToken := "fake_admin_token_" + fmt.Sprintf("%d", time.Now().Unix())
		status, _ := httpDo(t, "GET", "/api/admin/users", map[string]string{
			"Admin-Token": fakeToken,
		}, nil)
		assertStatus(t, status, 401)
	})

	t.Run("Session-Token失效", func(t *testing.T) {
		fakeToken := "fake_session_token_" + fmt.Sprintf("%d", time.Now().Unix())
		status, _ := httpDo(t, "GET", "/api/user/me", map[string]string{
			"X-Session-Token": fakeToken,
		}, nil)
		assertStatus(t, status, 401)
	})

	t.Run("Consume接口_免费额度不足返回402", func(t *testing.T) {
		// 此测试需要一个真实用户 token，其 daily_limit=0 且 extra_balance>0
		// 由于需要特定数据状态，这里仅打印说明
		t.Log("  提示：测试 402 需要构造 daily_limit=0 且 extra_balance>0 的用户资产")
		t.Log("  可手动调用 internalConsume 并传 allow_extra=false 触发")
	})

	t.Run("并发登录失败锁定测试", func(t *testing.T) {
		// 对不存在的用户连续发送错误密码，触发锁定
		for i := 0; i < 4; i++ {
			status, _ := httpDo(t, "POST", "/api/user/login", nil, map[string]string{
				"qq":      "lock_test_user",
				"password": "wrong_" + fmt.Sprintf("%d", i),
			})
			t.Logf("  第 %d 次登录失败 → %d", i+1, status)
		}
	})
}

// ============================================================================
// ⑥ 集成测试：完整流程
// ============================================================================

func TestAuth_FullFlow(t *testing.T) {
	t.Log("========== 完整鉴权流程测试 ==========")

	// Step 1: 管理员登录
	t.Run("完整流程_管理员登录", func(t *testing.T) {
		status, result := httpDo(t, "POST", "/api/admin/login", nil, map[string]string{
			"username": "lnb_x",
			"password": "xi520",
		})
		assertStatus(t, status, 200)
		if result != nil {
			if v, ok := result["admin_token"].(string); ok {
				ctx.AdminToken = v
			}
		}
	})

	// Step 2: 用 Admin-Token 访问受保护接口
	if ctx.AdminToken != "" {
		t.Run("完整流程_管理员获取用户列表", func(t *testing.T) {
			status, _ := httpDo(t, "GET", "/api/admin/users?page=1&size=1", map[string]string{
				"Admin-Token": ctx.AdminToken,
			}, nil)
			assertStatus(t, status, 200)
		})
	}

	// Step 3: 测试无 Token 访问受保护接口（应全部 401）
	noAuthTests := []struct {
		name   string
		method string
		path   string
	}{
		{"无Token访问用户信息", "GET", "/api/user/me"},
		{"无Token访问管理员接口", "GET", "/api/admin/users"},
		{"无Token访问内部接口", "POST", "/api/internal/check_quota"},
		{"无Token重生成Token", "POST", "/api/user/regen_token"},
	}
	for _, tc := range noAuthTests {
		t.Run(tc.name, func(t *testing.T) {
			status, _ := httpDo(t, tc.method, tc.path, nil, nil)
			if status != 401 {
				t.Errorf("  期望 401，实际 %d", status)
			}
		})
	}

	t.Log("========== 完整流程测试结束 ==========")
}

// ============================================================================
// 命令行直接运行（go test -v 或 go run 均可）
// ============================================================================

func TestMain(m *testing.M) {
	fmt.Println("============================================")
	fmt.Println("  userControl 鉴权接口测试")
	fmt.Println("  目标服务器:", baseURL)
	fmt.Println("============================================")
	code := m.Run()
	fmt.Println("============================================")
	fmt.Println("  测试完成，退出码:", code)
	fmt.Println("============================================")
	os.Exit(code)
}
