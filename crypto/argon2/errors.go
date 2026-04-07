package argon2

import "errors"

var (
	ErrInvalidPassword   = errors.New("invalid password")
	ErrInvalidHashFormat = errors.New("invalid hash format")
)
