package argon2

import (
	"github.com/seosoojin/dim/crypto"
	"github.com/seosoojin/dim/crypto/salt"

	"golang.org/x/crypto/argon2"
)

type argon2Crypto struct {
	opts *Argon2Options
}

func NewArgon2Crypto(opts ...argon2Options) *argon2Crypto {
	config := NewArgon2Options()

	for _, o := range opts {
		o(config)
	}

	return &argon2Crypto{
		opts: config,
	}
}

func (a *argon2Crypto) HashString(src string) ([]byte, salt.Salt, error) {
	salt, err := salt.Generate(a.opts.SaltLength)
	if err != nil {
		return nil, nil, err
	}

	hashed := argon2.IDKey([]byte(src), salt, a.opts.Time, a.opts.Memory, a.opts.Threads, a.opts.KeyLength)
	return hashed, salt, nil
}

func (a *argon2Crypto) VerifyHash(password string, salt salt.Salt, expectedHash []byte) bool {
	newHash := argon2.IDKey([]byte(password), salt, a.opts.Time, a.opts.Memory, a.opts.Threads, a.opts.KeyLength)
	return crypto.Compare(newHash, expectedHash)
}
