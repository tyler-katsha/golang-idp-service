package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)


var (
	ErrCipherTooSmall = errors.New("ciphertext too small")
)
type Encryptor struct {
	gcm cipher.AEAD
}

func NewEncryptor(key []byte) (*Encryptor, error) {
	block, err := aes.NewCipher(key)

	if err != nil {
		return nil,err
	}

	gcm, err := cipher.NewGCM(block)

	if err != nil {
		return nil,err
	}

	return &Encryptor{gcm: gcm},nil
}

func (e *Encryptor) Encrypt(plainText string) (string,error) {
	nonce := make([]byte,e.gcm.NonceSize())

	if _,err := io.ReadFull(rand.Reader,nonce); err != nil {
		return "",err
	}

	cipherText := e.gcm.Seal(nonce,nonce,[]byte(plainText),nil)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func (e *Encryptor) Decrypt(encoded string) (string,error) {
	data, err := base64.StdEncoding.DecodeString(encoded)

	if err != nil {
		return "",err
	}

	nonceSize := e.gcm.NonceSize()

	if len(data) < nonceSize {
		return "",ErrCipherTooSmall
	}

	nonce, cipherText := data[:nonceSize], data[nonceSize:]

	plainText, err := e.gcm.Open(nonce,nonce,cipherText,nil)

	if err != nil {
		return "",err
	}

	return string(plainText),nil
}