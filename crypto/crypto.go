package crypto

import "crypto/subtle"

type Crypto interface {
	HashString(src string) ([]byte, []byte, error)
}

func Compare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
