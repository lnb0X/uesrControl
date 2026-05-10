package utils

import (
	"io"
	"fmt"
	"log"
	"crypto/aes"
	"crypto/rand"
	"encoding/json"
	"crypto/cipher"
	"encoding/base64"

	"userControl/config"
)

var aesSecretKey []byte

func InitAES() {
	key := config.GetAESSecretKey()
	aesSecretKey = []byte(key)

	// 校验密钥长度：AES 仅支持 16/24/32 字节
	kLen := len(aesSecretKey)
	if kLen != 16 && kLen != 24 && kLen != 32 {
		log.Fatalf("[AES] 密钥长度无效：当前 %d 字节，仅支持 16(AES-128)/24(AES-192)/32(AES-256) 字节", kLen)
	}
	// 预创建 cipher 验证密钥可用
	if _, err := aes.NewCipher(aesSecretKey); err != nil {
		log.Fatalf("[AES] 密钥无效，无法创建 cipher: %v", err)
	}
	fmt.Printf("[AES] 初始化成功，密钥长度 %d 字节 (AES-%d)\n", kLen, kLen*8)
}

type CdkData struct {
	ScopeType  int16  `json:"st"`
	ScopeValue string `json:"sv"`
	CardType   int16  `json:"ct"`
	ApiName    string `json:"api"`
	FaceValue  int    `json:"val"`
	ExpiresAt  int64  `json:"exp"`
	MaxUses    int    `json:"mu"` // 最大使用次数，0=不限次数
	RandTag    string `json:"rnd"`
}

func EncryptCDK(data CdkData) (string, error) {
	plaintext, _ := json.Marshal(data)
	block, _ := aes.NewCipher(aesSecretKey)
	aesGCM, _ := cipher.NewGCM(block)

	nonce := make([]byte, aesGCM.NonceSize())
	io.ReadFull(rand.Reader, nonce)

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func DecryptCDK(encryptedStr string) (*CdkData, error) {
	data, err := base64.URLEncoding.DecodeString(encryptedStr)
	if err != nil {
		return nil, err
	}

	block, _ := aes.NewCipher(aesSecretKey)
	aesGCM, _ := cipher.NewGCM(block)

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("invalid cdk")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	var res CdkData
	json.Unmarshal(plaintext, &res)
	return &res, nil
}