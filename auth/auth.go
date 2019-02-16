package auth

import (
	"encoding/json"
	pbauth "github.com/hwsc-org/hwsc-api-blocks/lib"
	"github.com/hwsc-org/hwsc-lib/consts"
	"strings"
	"time"
)

// Authority ensures the identification is authorized.
type Authority struct {
	id                 *pbauth.Identification
	header             *Header
	body               *Body
	permissionRequired Permission
}

// Authorize the identification and generates the body.
// Returns an error if not authorized
func (a *Authority) Authorize(id *pbauth.Identification, permissionRequired Permission) error {
	if err := validateIdentification(id); err != nil {
		return err
	}
	// a.header and a.body can be nil because we generate the body on Validate()
	a.id = id
	a.permissionRequired = permissionRequired
	if err := a.Validate(); err != nil {
		return err
	}
	return nil
}

// Invalidate the token.
func (a *Authority) Invalidate() {
	a.id = nil
	a.header = nil
	a.body = nil
	a.permissionRequired = NoPermission
}

// Validate checks if the token is authorized using a secret.
// Returns an error if not valid.
func (a *Authority) Validate() error {
	if err := validateIdentification(a.id); err != nil {
		return err
	}
	tokenSignature := strings.Split(a.id.GetToken(), ".")
	// check 1: do we have a header, body, and signature?
	if len(tokenSignature) != 3 {
		return consts.ErrIncompleteToken
	}
	// check 2: decode header
	decodedHeader, err := base64Decode(tokenSignature[0])
	if err != nil {
		return err
	}
	// check 3: decode header
	// a.header is mutated here
	if err := json.Unmarshal([]byte(decodedHeader), a.header); err != nil {
		return err
	}
	// check 4: decode body
	decodedBody, err := base64Decode(tokenSignature[1])
	if err != nil {
		return err
	}
	// check 5: parses body from string to a struct
	// a.body is mutated here
	if err := json.Unmarshal([]byte(decodedBody), a.body); err != nil {
		return err
	}
	// check 6: checks permission requirement
	if a.body.Permission < a.permissionRequired {
		return consts.ErrInvalidPermission
	}
	// check 7: check expiration
	if a.HasExpired() {
		return consts.ErrExpiredToken
	}
	// check 8: rebuild the signature using the secret
	suspectedSignature, err := buildTokenSignature(tokenSignature[0], tokenSignature[1], a.header.Alg, a.id.GetSecret())
	if err != nil {
		return err
	}
	// the signature in the token should be the same with the suspected signature
	if a.id.GetToken() != suspectedSignature {
		return consts.ErrInvalidSignature
	}
	return nil
}

// HasExpired checks if the token has expired.
// Returns true if token has expired, or invalid header or body
func (a *Authority) HasExpired() bool {
	if err := validateHeader(a.header); err != nil {
		return true
	}
	if err := validateBody(a.body); err != nil {
		return true
	}
	expirationTime := a.body.ExpirationTimestamp
	if expirationTime == 0 || time.Now().UTC().Unix() >= expirationTime {
		return true
	}
	return false
}
