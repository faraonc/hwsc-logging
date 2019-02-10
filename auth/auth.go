package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	pb "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-app-gateway-svc/proto"
	"strconv"
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

func(a *Authority) decode() {
	// TODO error checking
	buffer := bytes.Buffer{}
	buffer.WriteString(token.Uuid)
	buffer.WriteString(token.PermissionLevel.String())
	buffer.WriteString(strconv.FormatInt(token.ExpirationTimestamp, 10))
	encodedStr := base64Encode(buffer.String())
	token.TokenString = hash(encodedStr, secret.secret)
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
	expirationTime := a.token.ExpirationTimestamp
	if expirationTime == 0 {
		return false
	}
	return time.Now().After(time.Unix(expirationTime, 0))
}

// IsAuthorized checks if the Token is authorized using a Secret
func (a *Authority) IsAuthorized() bool {
	return a.isValid
}


func Encode(token *pb.Token, secret *pb.Secret) {
	// TODO error checking
	buffer := bytes.Buffer{}
	buffer.WriteString(token.Uuid)
	buffer.WriteString(token.PermissionLevel.String())
	buffer.WriteString(strconv.FormatInt(token.ExpirationTimestamp, 10))
	encodedStr := base64Encode(buffer.String())
	token.TokenString = hash(encodedStr, secret.secret)
}


// base64Encode takes in a string and returns a base 64 encoded string
func base64Encode(src string) string {
	return strings.
		Trim(base64.URLEncoding.
			EncodeToString([]byte(src)), "=") // TODO remove cutset
}
// base64Encode takes in a base 64 encoded string and returns the //actual string or an error of it fails to decode the string
func base64Decode(src string) (string, error) {
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

// hash generates a Hmac256 hash of a string using a secret
func hash(src string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(src))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// isValidHash validates a hash against a tokenStr
func isValidHash(tokenStr string, hashed string, secret string) bool {
	return hashed == hash(value, secret)
}