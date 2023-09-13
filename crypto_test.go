package crypto_test

import (
	"strings"
	"testing"

	"github.com/gomig/crypto"
)

const algo crypto.HashAlgo = crypto.SHA3256

func cr() crypto.Crypto {
	return crypto.NewCryptography("S0Me SeCure KeY")
}

func TestHash(t *testing.T) {
	_, err := cr().Hash("Some Data", algo)
	if err != nil {
		t.Fatal(err)
	}
}

func TestHashFilename(t *testing.T) {
	hash, err := cr().HashFilename("file.jpg", algo)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasSuffix(hash, ".jpg") {
		t.Errorf("failed to generate hash file name!")
	}
}

func TestHashSize(t *testing.T) {
	if cr().HashSize(algo) != 64 {
		t.Error("invalid hash size!")
	}
}

func TestCheck(t *testing.T) {
	hash, err := cr().Hash("My Password", algo)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := cr().Check("My Password", hash, algo)
	if err != nil {
		t.Fatal(err)
	}

	if !ok {
		t.Error("failed to check hash!")
	}
}

func TestEncrypt(t *testing.T) {
	_, err := cr().Encrypt([]byte("Some Data"))
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecrypt(t *testing.T) {
	enc, err := cr().Encrypt([]byte("Data To Enc"))
	if err != nil {
		t.Fatal(err)
	}

	dec, err := cr().Decrypt(enc)
	if err != nil {
		t.Fatal(err)
	}

	if string(dec) != "Data To Enc" {
		t.Error("failed to decrypt data")
	}
}

func TestEncryptHEX(t *testing.T) {
	_, err := cr().EncryptHEX([]byte("Some Data"))
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecryptHex(t *testing.T) {
	enc, err := cr().EncryptHEX([]byte("Data To Enc"))
	if err != nil {
		t.Fatal(err)
	}

	dec, err := cr().DecryptHex(enc)
	if err != nil {
		t.Fatal(err)
	}

	if string(dec) != "Data To Enc" {
		t.Error("failed to decrypt data")
	}
}

func TestEncryptBase64(t *testing.T) {
	_, err := cr().EncryptBase64([]byte("Some Data"))
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecryptBase64(t *testing.T) {
	enc, err := cr().EncryptBase64([]byte("Data To Enc"))
	if err != nil {
		t.Fatal(err)
	}

	dec, err := cr().DecryptBase64(enc)
	if err != nil {
		t.Fatal(err)
	}

	if string(dec) != "Data To Enc" {
		t.Error("failed to decrypt data")
	}
}
