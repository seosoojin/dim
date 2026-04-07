package argon2

type Argon2Options struct {
	SaltLength uint32
	KeyLength  uint32
	Time       uint32
	Memory     uint32
	Threads    uint8
}

type argon2Options func(*Argon2Options)

func NewArgon2Options() *Argon2Options {
	return &Argon2Options{
		SaltLength: 16,
		KeyLength:  32,
		Time:       1,
		Memory:     64 << 10,
		Threads:    4,
	}
}

func WithSaltLength(saltLength uint32) argon2Options {
	return func(opts *Argon2Options) {
		opts.SaltLength = saltLength
	}
}

func WithKeyLength(keyLength uint32) argon2Options {
	return func(opts *Argon2Options) {
		opts.KeyLength = keyLength
	}
}

func WithTime(time uint32) argon2Options {
	return func(opts *Argon2Options) {
		opts.Time = time
	}
}

func WithMemory(memory uint32) argon2Options {
	return func(opts *Argon2Options) {
		opts.Memory = memory
	}
}

func WithThreads(threads uint8) argon2Options {
	return func(opts *Argon2Options) {
		opts.Threads = threads
	}
}
