package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	pbauth "github.com/hwsc-org/hwsc-api-blocks/lib"
	"github.com/hwsc-org/hwsc-lib/consts"
	"github.com/hwsc-org/hwsc-lib/validation"
	"hash"
	"strings"
	"time"
)

func validateIdentification(id *pbauth.Identification) error {
	if id == nil {
		return consts.ErrNilIdentification
	}
	if strings.TrimSpace(id.GetToken()) == "" {
		return consts.ErrEmptyToken
	}
	if err := validateSecret(id.GetSecret()); err != nil {
		return err
	}
	return nil
}

func validateHeader(header *Header) error {
	if header == nil {
		return consts.ErrNilHeader
	}
	return nil
}

func validateBody(body *Body) error {
	if body == nil {
		return consts.ErrNilBody
	}
	if err := validation.ValidateUserUUID(body.UUID); err != nil {
		return err
	}
	// Expiration timestamp is not verified
	return nil
}

func validateSecret(secret *pbauth.Secret) error {
	if secret == nil {
		return consts.ErrNilSecret
	}
	if strings.TrimSpace(secret.Key) == "" {
		return consts.ErrEmptySecret
	}
	createTime := secret.CreatedTimestamp
	if createTime == 0 || createTime >= time.Now().UTC().Unix() {
		return consts.ErrInvalidSecretCreateTimestamp
	}
	expirationTime := secret.ExpirationTimestamp
	if expirationTime == 0 || time.Now().UTC().Unix() >= expirationTime {
		return consts.ErrExpiredSecret
	}
	return nil
}

// NewToken generates token string using a header, body, and secret.
// Return error if an error exists during signing.
func NewToken(header *Header, body *Body, secret *pbauth.Secret) (string, error) {
	if err := validateHeader(header); err != nil {
		return "", err
	}
	if err := validateBody(body); err != nil {
		return "", err
	}
	if err := validateSecret(secret); err != nil {
		return "", err
	}
	// token expires in 2 hours
	body.ExpirationTimestamp = time.Now().UTC().Add(time.Hour * time.Duration(2)).Unix()
	tokenString, err := getTokenSignature(header, body, secret)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// getTokenSignature gets the token signature using the encoded header, body, and secret key.
// Return error if an error exists during signing.
func getTokenSignature(header *Header, body *Body, secret *pbauth.Secret) (string, error) {
	if err := validateHeader(header); err != nil {
		return "", err
	}
	if err := validateBody(body); err != nil {
		return "", err
	}
	if err := validateSecret(secret); err != nil {
		return "", err
	}
	// Token Signature = <encoded header>.<encoded body>.<hashed(<encoded header>.<encoded body>)>
	// 1. Encode the header
	encodedHeader, err := base64Encode(header)
	if err != nil {
		return "", err
	}
	// 2. Encode the body
	encodedBody, err := base64Encode(body)
	if err != nil {
		return "", err
	}
	// 3. Build <encoded header>.<encoded body>
	// 4. Build <hashed(<encoded header>.<encoded body>)>
	// 5. Build Token Signature = <encoded header>.<encoded body>.<hashed(<encoded header>.<encoded body>)>
	return buildTokenSignature(encodedHeader, encodedBody, header.Alg, secret)
}

// buildTokenSignature builds the token signature using the encoded header, body, selected algorithm, and secret key.
// Return error if an error exists during signing.
func buildTokenSignature(encodedHeader string, encodedBody string, alg Algorithm, secret *pbauth.Secret) (string, error) {
	if strings.TrimSpace(encodedHeader) == "" {
		return "", consts.ErrInvalidEncodedHeader
	}
	if strings.TrimSpace(encodedBody) == "" {
		return "", consts.ErrInvalidEncodedBody
	}
	if err := validateSecret(secret); err != nil {
		return "", err
	}
	// 3. Build <encoded header>.<encoded body>
	var bufferHeaderBody bytes.Buffer
	bufferHeaderBody.WriteString(encodedHeader)
	bufferHeaderBody.WriteString(".")
	bufferHeaderBody.WriteString(encodedBody)
	encodedHeaderBody := bufferHeaderBody.String()
	// 4. Build <hashed(<encoded header>.<encoded body>)>
	encodedSignature, err := hashSignature(alg, encodedHeaderBody, secret)
	if err != nil {
		return "", nil
	}
	// 5. Build Token Signature = <encoded header>.<encoded body>.<hashed(<encoded header>.<encoded body>)>
	var bufferTokenSignature bytes.Buffer
	bufferTokenSignature.WriteString(encodedHeaderBody)
	bufferTokenSignature.WriteString(".")
	bufferTokenSignature.WriteString(encodedSignature)
	return bufferTokenSignature.String(), nil
}

// base64Encode takes in a interface and encodes it as a string.
// Returns a base 64 encoded string or error during marshalling.
func base64Encode(src interface{}) (string, error) {
	srcMarshal, err := json.Marshal(src)
	if err != nil {
		return "", err
	}
	srcString := string(srcMarshal)
	// TODO maybe use Trim
	return strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(srcString)), "="), nil
}

// base64Encode takes in a base 64 encoded string.
// Returns the actual string or an error of it fails to decode the string.
func base64Decode(src string) (string, error) {
	if l := len(src) % 4; l > 0 {
		src += strings.Repeat("=", 4-l)
	}
	decoded, err := base64.URLEncoding.DecodeString(src)
	if err != nil {
		errMsg := fmt.Errorf("decoding error %s", err)
		return "", errMsg
	}
	return string(decoded), nil
}

// hashSignature generates a HMAC hash of a string using a secret
func hashSignature(alg Algorithm, signatureValue string, secret *pbauth.Secret) (string, error) {
	if strings.TrimSpace(signatureValue) == "" {
		return "", consts.ErrInvalidSignatureValue
	}
	if err := validateSecret(secret); err != nil {
		return "", err
	}
	key := []byte(secret.Key)
	var h hash.Hash
	switch alg {
	case Hs256:
		h = hmac.New(sha256.New, key)
	case Hs512:
		h = hmac.New(sha512.New, key)
	default:
		h = hmac.New(sha256.New, key)
	}
	h.Write([]byte(signatureValue))
	return base64.URLEncoding.EncodeToString(h.Sum(nil)), nil
}

// isValidHash validates a hash against a value
func isValidHash(alg Algorithm, signatureValue string, secret *pbauth.Secret, hashedValue string) bool {
	/*
		hashSignature cannot be reversed all you can do is hash the same character and compare it with a hashed value.
		If it evaluates to true, then the character is a what is in the hash.
		The isValidHash function only hashes the value with the secret and compared it with the hash.
	*/
	actualHashedValue, err := hashSignature(alg, signatureValue, secret)
	if err != nil {
		return false
	}
	return hashedValue == actualHashedValue
}
