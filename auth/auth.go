package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	pb "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-app-gateway-svc/proto"
	"github.com/hwsc-org/hwsc-lib/consts"
	"hash"
	"strings"
	"time"
)

// Authority ensures the identification is authorized.
type Authority struct {
	id                 *pb.Identification
	body               *Body
	permissionRequired Permission
}

// Authorize the identification and generates the body.
// Returns an error if not authorized
func (a *Authority) Authorize(id *pb.Identification, permissionRequired Permission) error {
	if a.id == nil {
		return consts.ErrNilIdentification
	}
	if a.id.Secret == nil {
		return consts.ErrNilSecret
	}
	// a.body can be nil because we generate the body on Validate()
	if strings.TrimSpace(id.Token) == "" {
		return consts.ErrEmptyToken
	}
	a.permissionRequired = permissionRequired
	if err := a.Validate(); err != nil {
		return err
	}
	return nil
}

// Invalidate the token.
func (a *Authority) Invalidate() {
	a.id = nil
	a.body = nil
}

// Validate checks if the token is authorized using a secret.
// Returns an error if not valid.
func (a *Authority) Validate() error {
	if a.id == nil {
		return consts.ErrNilIdentification
	}
	if a.body == nil {
		return consts.ErrNilBody
	}
	tokenSignature := strings.Split(a.id.Token, ".")
	// check 1: do we have a header, body, and signature?
	if len(tokenSignature) != 3 {
		return consts.ErrIncompleteToken
	}
	// check 2: decode body
	decodedBody, err := base64Decode(tokenSignature[1])
	if err != nil {
		return err
	}
	// check 3: parses body from string to a struct
	// a.body here is mutated
	if err := json.Unmarshal([]byte(decodedBody), a.body); err != nil {
		return err
	}
	// check 4: checks permission requirement
	if a.body.Permission < a.permissionRequired {
		return consts.ErrInvalidPermission
	}
	// check 5: check expiration
	if a.HasExpired() {
		return consts.ErrExpiredToken
	}
	// check 6: rebuild the signature using the secret
	suspectedSignature := buildTokenSignature(tokenSignature[0], tokenSignature[1], a.id.Header.Alg, a.id.Secret)
	// the signature in the token should be the same with the suspected signature
	if a.id.Token != suspectedSignature {
		return consts.ErrInvalidSignature
	}
	return nil
}

// HasExpired checks if the token has expired.
// Returns true if token has expired or body is nil.
func (a *Authority) HasExpired() bool {
	if a.body == nil {
		return true
	}
	expirationTime := a.body.ExpirationTimestamp
	if expirationTime == 0 {
		return true
	}
	if time.Now().After(time.Unix(expirationTime, 0)) {
		return true
	}
	return false
}

// NewToken generates token string using a header, body, and secret.
// Return error if an error exists during signing.
func NewToken(header *pb.Header, body *Body, secret *pb.Secret) (string, error) {
	// token expires in 2 hours
	body.ExpirationTimestamp = time.Now().Add(time.Hour * time.Duration(2)).Unix()
	tokenString, err := getTokenSignature(header, body, secret)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// getTokenSignature gets the token signature using the encoded header, body, and secret key.
// Return error if an error exists during signing.
func getTokenSignature(header *pb.Header, body *Body, secret *pb.Secret) (string, error) {
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
	return buildTokenSignature(encodedHeader, encodedBody, header.Alg, secret), nil
}

// buildTokenSignature builds the token signature using the encoded header, body, selected algorithm, and secret key.
// Returns the token string.
func buildTokenSignature(encodedHeader string, encodedBody string, alg pb.Algorithm, secret *pb.Secret) string {
	// 3. Build <encoded header>.<encoded body>
	var bufferHeaderBody bytes.Buffer
	bufferHeaderBody.WriteString(encodedHeader)
	bufferHeaderBody.WriteString(".")
	bufferHeaderBody.WriteString(encodedBody)
	encodedHeaderBody := bufferHeaderBody.String()
	// 4. Build <hashed(<encoded header>.<encoded body>)>
	encodedSignature := hashSignature(alg, encodedHeaderBody, secret)

	// 5. Build Token Signature = <encoded header>.<encoded body>.<hashed(<encoded header>.<encoded body>)>
	var bufferTokenSignature bytes.Buffer
	bufferTokenSignature.WriteString(encodedHeaderBody)
	bufferTokenSignature.WriteString(".")
	bufferTokenSignature.WriteString(encodedSignature)

	return bufferTokenSignature.String()
}

// base64Encode takes in a interface and encodes it as a string.
// Returns a base 64 encoded string.
func base64Encode(src interface{}) (string, error) {
	// TODO maybe use Trim
	srcMarshal, err := json.Marshal(src)
	if err != nil {
		return "", err
	}
	srcString := string(srcMarshal)
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
func hashSignature(alg pb.Algorithm, signatureValue string, secret *pb.Secret) string {
	// TODO pre check for error
	key := []byte(secret.Key)
	var h hash.Hash
	switch alg {
	case pb.Algorithm_HS256:
		h = hmac.New(sha256.New, key)
	case pb.Algorithm_HS512:
		h = hmac.New(sha512.New, key)
	default:
		h = hmac.New(sha256.New, key)
	}
	h.Write([]byte(signatureValue))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// isValidHash validates a hash against a value
func isValidHash(alg pb.Algorithm, signatureValue string, secret *pb.Secret, hashedValue string) bool {
	/*
		NB: hashSignature cannot be reversed all you can do is hash the same character and compare it with a hashed value. If it evaluates to true, then the character is a what is in the hash.
		The isValidHash function only hashes the value with the secret and compared it with the hash
		Above we created two methods, One for generating an HS256 hash and the other for validating a string against a hash.
	*/
	return hashedValue == hashSignature(alg, signatureValue, secret)
}
