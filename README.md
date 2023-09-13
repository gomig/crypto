# Crypto

Cryptography library with support of MD4, MD5, SHA1, SHA256, SHA256224, SHA512, SHA512224, SHA512256, SHA384, SHA3224, SHA3256, SHA3384, SHA3512, KECCAK256 and KECCAK512 algorithms.

## Create New Crypto Driver

**Caution:** This function generate panic if key is empty!

```go
import "github.com/gomig/crypto"
crp := crypto.NewCryptography("my-secret-key")
```

## Hash Algorithm Type

Crypto driver use `HashAlgo` type for algorithm params. this type can parsed from string or predefined constant.

```go
import "github.com/gomig/crypto"
var a crypto.HashAlgo
a.Parse("md4")

// Or Set Manually
a = crypto.MD5
```

## Usage

Crypto interface contains following methods:

### Hash

Make hash for data.

```go
// Signature:
Hash(data string, algo HashAlgo) (string, error)

// Example:
import "github.com/gomig/crypto"
h, err := crp.Hash("my data", crypto.MD5)
```

### HashFilename

Make hashed filename based on current timestamp.

```go
// Signature:
HashFilename(filename string, algo HashAlgo) (string, error)

// Example:
import "github.com/gomig/crypto"
h, err := crp.HashFilename("myfile.jpg", crypto.MD5) // => a1469c8565fc80b55220324eb3056d3e.jpg
```

### HashSize

Get hash size for algorithm. return -1 if invalid algo passed or on error.

```go
// Signature:
HashSize(algo HashAlgo) int

// Example:
import "github.com/gomig/crypto"
size := crp.HashSize(crypto.MD5) // => 16
```

### Check

Check data against hash.

```go
// Signature:
Check(data string, hash string, algo HashAlgo) (bool, error)

// Example:
import "github.com/gomig/crypto"
ok, err := crp.Check("my-password", "a1469c8565fc80b55220324eb3056d3e", crypto.MD5)
```

### Encrypt

Encrypt data.

**Note:** This function returns raw byte array, if you need string version of encrypted data use `EncryptHEX` or `EncryptBase64`.

```go
// Signature:
Encrypt(data []byte) ([]byte, error)

// Example:
data, err := crp.Encrypt([]byte("my data to enc"))
```

### Decrypt

Decrypt data.

**Note:** This function accept raw byte array as input. if you need to decrypt Hex or Base64 encoded data use `DecryptHex` or `DecryptBase64`.

```go
// Signature:
Decrypt(data []byte) ([]byte, error)

// Example:
data, err := crp.Decrypt(dataBytes)
```

### EncryptHEX

Encrypt data and return encrypted value as hex encoded string.

```go
// Signature:
EncryptHEX(data []byte) (string, error)

// Example:
data, err := crp.EncryptHEX([]byte("my data"))
```

### DecryptHex

Decrypt data from hex encoded string.

```go
// Signature:
DecryptHex(hexString string) ([]byte, error)

// Example:
res, err := crp.DecryptHex(encHexData)
```

### EncryptBase64

Encrypt data and return encrypted value as base64 encoded string.

```go
// Signature:
EncryptBase64(data []byte) (string, error)

// Example:
data, err := crp.EncryptBase64([]byte("my data"))
```

### DecryptBase64

Decrypt data from base64 encoded string.

```go
// Signature:
DecryptBase64(base64String string) ([]byte, error)

// Example
res, err := crp.DecryptBase64(encBase64Data)
```
