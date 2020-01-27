package crypto

// Hector Oliveros - 2019
// hector.oliveros.leon@gmail.com

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"io"
	"time"
)

const DefaultHashCost = bcrypt.MinCost
const JWTSigningMethod = "HS256"

var HashCost = func() int { return DefaultHashCost }

type Claims struct {
	Type string `json:"name"`
	jwt.StandardClaims
}

var (
	ErrorInvalidSignature = errors.New("invalid token signature")
	ErrorMalformedToken   = errors.New("invalid malformed token")
	ErrorExpiredToken     = errors.New("expired token")
	ErrorUnableToHandle   = errors.New("unable to handle")
)

func ValidateJWTToken(tokenOrig []byte, secret []byte) error {
	token, err := jwt.Parse(string(tokenOrig), func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err == nil && token.Valid {
		return nil
	}
	ve, ok := err.(*jwt.ValidationError)
	if !ok || ve.Errors&jwt.ValidationErrorSignatureInvalid != 0 {
		return ErrorInvalidSignature
	}
	if ve.Errors&jwt.ValidationErrorMalformed != 0 {
		return ErrorMalformedToken
	}

	if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
		// Token is either expired or not active yet
		return ErrorExpiredToken
	}
	return ErrorUnableToHandle
}

func CreateJWTTokenString(c *Claims, secret []byte, d time.Duration) (string, error) {
	c.ExpiresAt = time.Now().Add(d).Unix()
	c.IssuedAt = time.Now().Unix()
	token := jwt.NewWithClaims(jwt.GetSigningMethod(JWTSigningMethod), c)
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func SetHashCost(f func() int) {
	if f == nil {
		return
	}
	HashCost = f
}

// hash and encode password
func EncodePassword(plainPWD []byte, key []byte) ([]byte, error) {
	hash := hashAndSalt(plainPWD)
	encHash, err := EncryptAES(hash, key)
	if err != nil {
		return encHash, err
	}
	return encHash, nil
}

// Compare one plan text password with encrypted password
// if encPWD is not the hash of the plainPWD then return false and nil error
// If there is an error in the process, then the error returns.
// if this happens it is possible that it is an attack on the system and an alert should occur
func CheckPassword(plainPWD []byte, encPWD []byte, key []byte) (bool, error) {
	decPWD, err := DecryptAES(encPWD, key)
	if err != nil {
		return false, err
	}
	err = bcrypt.CompareHashAndPassword(decPWD, plainPWD)
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, err
}

func hashAndSalt(pwd []byte) []byte {
	// Use GenerateFromPassword to hash & salt pwd
	hash, err := bcrypt.GenerateFromPassword(pwd, HashCost())
	if err != nil {
		// TODO: Sentry
		return []byte{}
	}
	return hash
}

func EncryptAES(plaintext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func DecryptAES(cipherText []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize {
		return nil, fmt.Errorf("cipherText too short. Must be at least %d", nonceSize)
	}

	nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]
	return gcm.Open(nil, nonce, cipherText, nil)
}

func GenerateRandomRSAKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	// Generate RSA Keys
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil
	}
	return pk, &pk.PublicKey
}

func EncryptRSA(text string, publicKey *rsa.PublicKey) ([]byte, error) {
	message := []byte(text)
	encryptedTxt, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, message, nil)
	if err != nil {
		return nil, err
	}
	return encryptedTxt, nil
}

func DecryptRSA(text []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	plainText, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, text, nil)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func ParseRSAPrivateKey(b64Key string) (key *rsa.PrivateKey, err error) {
	data, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(data)
}
