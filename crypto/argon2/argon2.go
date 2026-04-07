package argon2

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/seosoojin/dim/crypto"
	"github.com/seosoojin/dim/crypto/salt"

	"golang.org/x/crypto/argon2"
)

type argon2Crypto struct {
	opts *Argon2Options
}

var _ crypto.Crypto = (*argon2Crypto)(nil)

func NewArgon2Crypto(opts ...argon2Options) *argon2Crypto {
	config := NewArgon2Options()

	for _, o := range opts {
		o(config)
	}

	return &argon2Crypto{
		opts: config,
	}
}

func (a *argon2Crypto) HashString(src string) ([]byte, error) {
	salt, err := salt.Generate(a.opts.SaltLength)
	if err != nil {
		return nil, err
	}

	return a.hashString(src, salt), nil
}

func (a *argon2Crypto) hashString(src string, salt salt.Salt) []byte {
	hash := argon2.IDKey([]byte(src), salt, a.opts.Time, a.opts.Memory, a.opts.Threads, a.opts.KeyLength)

	encodedHash := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		a.opts.Memory,
		a.opts.Time,
		a.opts.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	return []byte(encodedHash)
}

func (a *argon2Crypto) VerifyHash(password string, expectedHash []byte) (bool, error) {
	config, salt, expectedHashBytes, err := a.ExtractComponents(expectedHash)
	if err != nil {
		return false, err
	}

	log.Printf("Extracted config: %+v", config)
	log.Printf("Extracted salt: %x\n", salt)
	log.Printf("Extracted hash: %x\n", expectedHashBytes)

	log.Printf("password %s", password)
	newHash := argon2.IDKey([]byte(password), salt, config.Time, config.Memory, config.Threads, config.KeyLength)
	return crypto.Compare(newHash, expectedHashBytes), nil
}

func (a *argon2Crypto) ExtractComponents(encodedHash []byte) (Argon2Options, salt.Salt, []byte, error) {
	if !bytes.HasPrefix(encodedHash, []byte("$argon2id$")) {
		return Argon2Options{}, nil, nil, ErrInvalidHashFormat
	}

	components := bytes.Split(encodedHash, []byte("$"))
	if len(components) != 6 {
		return Argon2Options{}, nil, nil, ErrInvalidHashFormat
	}

	var config Argon2Options
	fmt.Sscanf(string(components[3]), "m=%d,t=%d,p=%d",
		&config.Memory, &config.Time, &config.Threads)

	if config.Memory == 0 || config.Time == 0 || config.Threads == 0 {
		return Argon2Options{}, nil, nil, ErrInvalidHashFormat
	}

	saltBytes, err := base64.RawStdEncoding.DecodeString(string(components[4]))
	if err != nil {
		return Argon2Options{}, nil, nil, err
	}

	hashBytes, err := base64.RawStdEncoding.DecodeString(string(components[5]))
	if err != nil {
		return Argon2Options{}, nil, nil, err
	}

	config.SaltLength = uint32(len(saltBytes))
	config.KeyLength = uint32(len(hashBytes))

	return config, saltBytes, hashBytes, nil
}
