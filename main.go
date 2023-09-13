package crypto

// NewCryptography create a new cryptography instance
func NewCryptography(key string) Crypto {
	c := new(cryptoDriver)
	c.key = key
	return c
}
