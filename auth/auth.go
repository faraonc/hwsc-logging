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
	"hash"
	"strings"
	"time"
)

type Authority struct {
	token   *pb.Token
	secret  *pb.Secret
	isValid bool
}

// Authorize the given Token using a Secret
func (a *Authority) Authorize(token *pb.Token, secret *pb.Secret) error {
	// TODO decode the Token using the Secret and set isValid to true or false
	// return error as necessary
	//
	return nil
}

func (a *Authority) decode() {
	// TODO error checking
}

// Invalidate the Token
func (a *Authority) Invalidate() {
	a.token = nil
	a.secret = nil
	a.isValid = false
}

// HasExpired checks if the Token has expired
// Returns false if token has expired or timestamp is nil
func (a *Authority) HasExpired() bool {
	expirationTime := a.token.Payload.ExpirationTimestamp
	if expirationTime == 0 {
		return false
	}
	return time.Now().After(time.Unix(expirationTime, 0))
}

// IsAuthorized checks if the Token is authorized using a Secret
func (a *Authority) IsAuthorized() bool {
	return a.isValid
}

func NewToken(alg pb.Algorithm, typ pb.Type, uuid string, permission pb.Permission, secret *pb.Secret)(*pb.Token, error){
	header := &pb.Header{
		Alg: alg,
		Typ: typ,
	}

	payload := &pb.Payload{
		Uuid: uuid,
		PermissionLevel: permission,
	}

	token := &pb.Token{
		Header: header,
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
	headerEncoded, err:= Base64Encode(token.Header)
	if err != nil {
		return err
	}
	// 2. Encode the payload
	payloadEncoded, err := Base64Encode(token.Payload)
	if err != nil {
		return err
	}
	// 3. Build <encoded header>.<encoded payload>
	var headerPayloadBuffer bytes.Buffer
	headerPayloadBuffer.WriteString(headerEncoded)
	headerPayloadBuffer.WriteString(".")
	headerPayloadBuffer.WriteString(payloadEncoded)
	headerPayloadEncoded := headerPayloadBuffer.String()
	// 4. Build <hashed(<encoded header>.<encoded payload>)>
	signatureEncoded := Hash(token.Header.Alg, headerPayloadEncoded, secret)

	// 5. Build Token Signature = <encoded header>.<encoded payload>.<hashed(<encoded header>.<encoded payload>)>
	var tokenSignatureBuffer bytes.Buffer
	tokenSignatureBuffer.WriteString(headerPayloadEncoded)
	tokenSignatureBuffer.WriteString(".")
	tokenSignatureBuffer.WriteString(signatureEncoded)
	token.Signature = tokenSignatureBuffer.String()

	return nil
}

// Base64Encode takes in a string.
// Returns a base 64 encoded string
func Base64Encode(src interface{}) (string, error) {
	// TODO maybe use Trim
	srcMarshal, err := json.Marshal(src)
	if err != nil {
		return "", err
	}
	srcString := string(srcMarshal)
	return strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(srcString)), "="), nil
}

// Base64Encode takes in a base 64 encoded string.
// Returns the actual string or an error of it fails to decode the string.
func Base64Decode(src string) (string, error) {
	if l := len(src) % 4; l > 0 {
		src += strings.Repeat("=", 4-l)
	}
	decoded, err := base64.URLEncoding.DecodeString(src)
	if err != nil {
		errMsg := fmt.Errorf("Decoding Error %s", err)
		return "", errMsg
	}
	return string(decoded), nil
}

// Hash generates a Hmac256 hash of a string using a secret
func Hash(alg pb.Algorithm, signatureValue string, secret *pb.Secret) string {
	// TODO pre check for error
	key := []byte(secret.Key)
	var h hash.Hash
	switch alg{
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
		NB: Hash cannot be reversed all you can do is hash the same character and compare it with a hashed value. If it evaluates to true, then the character is a what is in the hash.
		The isValidHash function only hashes the value with the secret and comared it with the hash
		Above we created two methods, One for generating an HS256 hash and the other for validating a string against a hash.
	*/
	return hashedValue == Hash(alg, signatureValue, secret)
}
