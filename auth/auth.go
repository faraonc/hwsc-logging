package auth

import (
	"encoding/json"
	pbauth "github.com/hwsc-org/hwsc-api-blocks/lib"
	"github.com/hwsc-org/hwsc-lib/consts"
	"strings"
)

// Authority ensures the identification is authorized.
type Authority struct {
	id                 *pbauth.Identification
	header             *Header
	body               *Body
	tokenRequired      TokenType
	permissionRequired Permission
}

// NewAuthority makes an authority for a service with the required token and permission level.
// The authority defaults to NoPermission if unknown permission level is used.
// Returns an authority with the embedded required token and permission level.
func NewAuthority(tokenRequired TokenType, permissionRequired Permission) Authority {
	permission := NoPermission
	if permissionRequired > NoPermission && permissionRequired <= Admin {
		permission = permissionRequired
	}
	token := NoType
	if tokenRequired > NoType && tokenRequired <= Jwt {
		token = tokenRequired
	}
	return Authority{
		header:             &Header{},
		body:               &Body{},
		tokenRequired:      token,
		permissionRequired: permission,
	}
}

// Authorize the identification and generates the body.
// Returns an error if not authorized.
func (a *Authority) Authorize(id *pbauth.Identification) error {
	if err := ValidateIdentification(id); err != nil {
		return err
	}
	a.id = id
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
	a.tokenRequired = NoType
	a.permissionRequired = NoPermission
}

// Validate checks if the token is authorized using a secret.
// Returns an error if not valid.
func (a *Authority) Validate() error {
	if err := ValidateIdentification(a.id); err != nil {
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
	if err := ValidateHeader(a.header); err != nil {
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
	// check expiration in body
	if err := ValidateBody(a.body); err != nil {
		return err
	}
	// check 6: checks permission requirement
	if a.body.Permission < a.permissionRequired {
		return consts.ErrInvalidPermission
	}
	if a.body.Permission == Admin && a.header.Alg != Hs512 {
		return consts.ErrInvalidPermission
	}
	// check 7: checks token type
	if a.header.TokenTyp != a.tokenRequired {
		return consts.ErrInvalidRequiredTokenType
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
	// Secret can expire, but not the token.
	if err := ValidateHeader(a.header); err != nil {
		return true
	}
	if err := ValidateBody(a.body); err != nil {
		return true
	}
	return false
}
