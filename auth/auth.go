package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	pb "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-app-gateway-svc/proto"
	"github.com/hwsc-org/hwsc-lib/consts"
	"hash"
	"strings"
	"time"
)

// Authority ensures the client is authorized.
type Authority struct {
	token  *pb.Token
	secret *pb.Secret
	// TODO incorporate permission level later
}

// Authorize the Token using a Secret
func (a *Authority) Authorize(token *pb.Token, secret *pb.Secret) error {
	if token == nil {
		return consts.ErrNilToken
	}
	if secret == nil {
		return consts.ErrNilSecret
	}
	if err := a.Validate(); err != nil {
		return err
	}
	return nil
}

// Invalidate the Token
func (a *Authority) Invalidate() {
	a.token = nil
	a.secret = nil
}

// IsAuthorized checks if the Token is authorized using a Secret
func (a *Authority) Validate() error {
	if a.HasExpired() {
		return errors.New("dipshit  expired")
	}
	if err := a.check(); err != nil {
		return err
	}
	return nil
}

// HasExpired checks if the Token has expired
// Returns true if token has expired or timestamp is nil
func (a *Authority) HasExpired() bool {
	expirationTime := a.token.Payload.ExpirationTimestamp
	if expirationTime == 0 {
		return true
	}
	if time.Now().After(time.Unix(expirationTime, 0)) {
		return true
	}
	return false
}

func (a *Authority) check() error {
	// TODO error checking
	tokenSignature := strings.Split(a.token.Signature, ".")
	// check if we have a header, payload, signature
	if len(tokenSignature) != 3 {
		return errors.New("invalid token: token should contain header, payload and secret")
	}

	// rebuild the signature using the secret
	var bufferHeaderPayload bytes.Buffer
	bufferHeaderPayload.WriteString(tokenSignature[0])
	bufferHeaderPayload.WriteString(".")
	bufferHeaderPayload.WriteString(tokenSignature[1])
	encodedHeaderPayload := bufferHeaderPayload.String()
	encodedSignature := hashSignature(a.token.Header.Alg, encodedHeaderPayload, a.secret)
	var bufferTokenSignature bytes.Buffer
	bufferTokenSignature.WriteString(encodedHeaderPayload)
	bufferTokenSignature.WriteString(".")
	bufferTokenSignature.WriteString(encodedSignature)
	suspectedSignature := bufferTokenSignature.String()

	// the signature in the token should be the same with the suspected signature
	if a.token.Signature != suspectedSignature {
		return errors.New("dipshit hacker")
	}
	return nil
}

func NewToken(alg pb.Algorithm, typ pb.Type, uuid string, permission pb.Permission, secret *pb.Secret) (*pb.Token, error) {
	header := &pb.Header{
		Alg: alg,
		Typ: typ,
	}

	payload := &pb.Payload{
		Uuid:            uuid,
		PermissionLevel: permission,
	}

	token := &pb.Token{
		Header:  header,
		Payload: payload,
	}
	if err := encode(token, secret); err != nil {
		return nil, err
	}
	// token expires in 2 hours
	token.Payload.ExpirationTimestamp = time.Now().Add(time.Hour * time.Duration(2)).Unix()

	return token, nil
}

func encode(token *pb.Token, secret *pb.Secret) error {
	// TODO pre-error checking
	// Token Signature = <encoded header>.<encoded payload>.<hashed(<encoded header>.<encoded payload>)>
	// 1. Encode the header
	encodedHeader, err := base64Encode(token.Header)
	if err != nil {
		return err
	}
	// 2. Encode the payload
	encodedPayload, err := base64Encode(token.Payload)
	if err != nil {
		return err
	}
	// 3. Build <encoded header>.<encoded payload>
	var bufferHeaderPayload bytes.Buffer
	bufferHeaderPayload.WriteString(encodedHeader)
	bufferHeaderPayload.WriteString(".")
	bufferHeaderPayload.WriteString(encodedPayload)
	encodedHeaderPayload := bufferHeaderPayload.String()
	// 4. Build <hashed(<encoded header>.<encoded payload>)>
	encodedSignature := hashSignature(token.Header.Alg, encodedHeaderPayload, secret)

	// 5. Build Token Signature = <encoded header>.<encoded payload>.<hashed(<encoded header>.<encoded payload>)>
	var bufferTokenSignature bytes.Buffer
	bufferTokenSignature.WriteString(encodedHeaderPayload)
	bufferTokenSignature.WriteString(".")
	bufferTokenSignature.WriteString(encodedSignature)
	token.Signature = bufferTokenSignature.String()

	return nil
}

// base64Encode takes in a string.
// Returns a base 64 encoded string
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
		The isValidHash function only hashes the value with the secret and comared it with the hash
		Above we created two methods, One for generating an HS256 hash and the other for validating a string against a hash.
	*/
	return hashedValue == hashSignature(alg, signatureValue, secret)
}
