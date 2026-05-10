package utils

import (
	"crypto/rand"
	"math/big"
	"regexp"
)

func IsValidQQNumber(qq string) bool {
	pattern := `^[1-9]\d{4,10}$`
	matched, _ := regexp.MatchString(pattern, qq)
	return matched
}

func GenerateCaptchaFull() string {
	const chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	result := make([]byte, 6)
	for i := 0; i < 6; i++ {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		result[i] = chars[n.Int64()]
	}

	return string(result)
}
