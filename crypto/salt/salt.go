package salt

import "crypto/rand"

type Salt []byte

func Generate(length uint32) (Salt, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	return salt, nil
}
