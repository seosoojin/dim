package crypto

import (
	"crypto/subtle"

	"github.com/seosoojin/dim/crypto/salt"
)

type Crypto interface {
	HashString(src string) ([]byte, salt.Salt, error)
	VerifyHash(password string, salt salt.Salt, expectedHash []byte) bool
}

func Compare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
