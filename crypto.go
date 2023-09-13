package crypto

// Crypto cryptography interface
type Crypto interface {
	// Hash make hash for data
	Hash(data string, algo HashAlgo) (string, error)
	// HashFilename make hashed filename based on current timestamp
	HashFilename(filename string, algo HashAlgo) (string, error)
	// HashSize get hash size for algorithm
	// return -1 if invalid algo passed
	HashSize(algo HashAlgo) int
	// Check check data against hash
	Check(data string, hash string, algo HashAlgo) (bool, error)
	// Encrypt data
	Encrypt(data []byte) ([]byte, error)
	// Decrypt data
	Decrypt(data []byte) ([]byte, error)
	// EncryptHEX encrypt data and return encrypted value as hex encoded string
	EncryptHEX(data []byte) (string, error)
	// DecryptHex decrypt data from hex encoded string.
	DecryptHex(hexString string) ([]byte, error)
	// EncryptBase64 encrypt data and return encrypted value as base64 encoded string
	EncryptBase64(data []byte) (string, error)
	// DecryptBase64 decrypt data from base64 encoded string.
	DecryptBase64(base64String string) ([]byte, error)
}
