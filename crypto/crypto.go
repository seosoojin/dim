package crypto

import (
	"crypto/subtle"
)

type Crypto interface {
	HashString(src string) ([]byte, error)
	VerifyHash(password string, expectedHash []byte) (bool, error)
}

func Compare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
