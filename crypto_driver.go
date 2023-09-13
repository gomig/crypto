package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"path/filepath"
	"time"

	"github.com/gomig/utils"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/sha3"
)

// cryptoDriver cryptography driver
type cryptoDriver struct {
	key string
}

func (cryptoDriver) err(format string, args ...any) error {
	return utils.TaggedError([]string{"Crypto"}, format, args...)
}

// Hash make hash for data
func (cd cryptoDriver) Hash(data string, algo HashAlgo) (string, error) {
	var hasher hash.Hash
	key := []byte(cd.key)

	switch algo {
	case MD4:
		hasher = hmac.New(md4.New, key)
	case MD5:
		hasher = hmac.New(md5.New, key)
	case SHA1:
		hasher = hmac.New(sha1.New, key)
	case SHA256:
		hasher = hmac.New(sha256.New, key)
	case SHA256224:
		hasher = hmac.New(sha256.New224, key)
	case SHA512:
		hasher = hmac.New(sha512.New, key)
	case SHA512224:
		hasher = hmac.New(sha512.New512_224, key)
	case SHA512256:
		hasher = hmac.New(sha512.New512_256, key)
	case SHA384:
		hasher = hmac.New(sha512.New384, key)
	case SHA3224:
		hasher = hmac.New(sha3.New224, key)
	case SHA3256:
		hasher = hmac.New(sha3.New256, key)
	case SHA3384:
		hasher = hmac.New(sha3.New384, key)
	case SHA3512:
		hasher = hmac.New(sha3.New512, key)
	case KECCAK256:
		hasher = hmac.New(sha3.NewLegacyKeccak256, key)
	case KECCAK512:
		hasher = hmac.New(sha3.NewLegacyKeccak512, key)
	}

	if hasher == nil {
		return "", cd.err("invalid hasher %s.", algo)
	}

	_, err := hasher.Write([]byte(data))
	if err != nil {
		return "", cd.err(err.Error())
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// HashFilename make hashed filename based on current timestamp
func (cd cryptoDriver) HashFilename(filename string, algo HashAlgo) (string, error) {
	ext := filepath.Ext(filename)
	res, err := cd.Hash(fmt.Sprintf("%s-at-%d", filename, time.Now().Nanosecond()), algo)
	if err != nil {
		return "", cd.err(err.Error())
	}
	return res + ext, nil
}

// HashSize get hash size for algorithm
// return -1 if invalid algo passed
func (cd cryptoDriver) HashSize(algo HashAlgo) int {
	h, err := cd.Hash("Test", algo)
	if err != nil {
		return -1
	}

	return len(h)
}

// Check check data against hash
func (cd cryptoDriver) Check(data string, hash string, algo HashAlgo) (bool, error) {
	res, err := cd.Hash(data, algo)
	if err != nil {
		return false, cd.err(err.Error())
	}
	return res == hash, nil
}

// Encrypt data
func (cd cryptoDriver) Encrypt(data []byte) ([]byte, error) {
	var err error

	// generate key md5
	key, err := cd.Hash(cd.key, MD5)
	if err != nil {
		return nil, cd.err(err.Error())
	}

	// generate cipher
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, cd.err(err.Error())
	}

	// generate gcm
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, cd.err(err.Error())
	}

	// generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, cd.err(err.Error())
	}

	// encrypt data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt data
func (cd cryptoDriver) Decrypt(data []byte) ([]byte, error) {
	var err error

	// generate key md5
	key, err := cd.Hash(cd.key, MD5)
	if err != nil {
		return nil, cd.err(err.Error())
	}

	// generate cipher
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, cd.err(err.Error())
	}

	// generate gcm
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, cd.err(err.Error())
	}

	// generate nonce
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, cd.err(err.Error())
	}

	return plaintext, nil
}

// EncryptHEX encrypt data and return encrypted value as hex encoded string
func (cd cryptoDriver) EncryptHEX(data []byte) (string, error) {
	res, err := cd.Encrypt(data)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(res), nil
}

// DecryptHex decrypt data from hex encoded string.
func (cd cryptoDriver) DecryptHex(hexString string) ([]byte, error) {
	data, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, cd.err(err.Error())
	}
	return cd.Decrypt(data)
}

// EncryptBase64 encrypt data and return encrypted value as base64 encoded string
func (cd cryptoDriver) EncryptBase64(data []byte) (string, error) {
	res, err := cd.Encrypt(data)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(res), nil
}

// DecryptBase64 decrypt data from base64 encoded string.
func (cd cryptoDriver) DecryptBase64(base64String string) ([]byte, error) {
	data, err := base64.URLEncoding.DecodeString(base64String)
	if err != nil {
		return nil, cd.err(err.Error())
	}
	return cd.Decrypt(data)
}
