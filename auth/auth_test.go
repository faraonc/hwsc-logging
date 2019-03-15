package auth

import (
	"errors"
	pbauth "github.com/hwsc-org/hwsc-api-blocks/protobuf/lib"
	"github.com/hwsc-org/hwsc-lib/consts"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestNewAuthority(t *testing.T) {
	cases := []struct {
		desc          string
		requiredToken TokenType
		expToken      TokenType
		requiredPerm  Permission
		expPermLevel  Permission
	}{
		{"test for negative token type", NoType - 1, NoType, -1, NoPermission},
		{"test for over max token type", Jwt + 1, NoType, -1, NoPermission},
		{"test for negative permission", NoType, NoType, NoPermission - 1, NoPermission},
		{"test for negative permission", Jwt, Jwt, -1, NoPermission},
		{"test for NoPermission", NoType, NoType, NoPermission, NoPermission},
		{"test for UserRegistration", NoType, NoType, UserRegistration, UserRegistration},
		{"test for User", NoType, NoType, User, User},
		{"test for Admin", NoType, NoType, Admin, Admin},
		{"test for over permission", NoType, NoType, Admin + 1, NoPermission},
	}
	for _, c := range cases {
		a := NewAuthority(c.requiredToken, c.requiredPerm)
		assert.Equal(t, c.expPermLevel, a.permissionRequired, c.desc)
		assert.Equal(t, c.expToken, a.tokenRequired, c.desc)
	}
}

func TestAuthorize(t *testing.T) {
	cases := []struct {
		desc          string
		id            *pbauth.Identification
		isExpErr      bool
		expErr        error
		requiredPerm  Permission
		requiredToken TokenType
	}{
		{"test for nil identification", nil, true, consts.ErrNilIdentification, NoPermission, NoType},
		{"test for empty token string", &pbauth.Identification{}, true, consts.ErrEmptyToken, NoPermission, NoType},
		{"test for nil secret",
			&pbauth.Identification{
				Token: valid512JWTAdminTokenString,
			}, true, consts.ErrNilSecret, NoPermission, NoType,
		},
		{"test for secret empty key",
			&pbauth.Identification{
				Token:  valid512JWTAdminTokenString,
				Secret: &pbauth.Secret{},
			}, true, consts.ErrEmptySecret, NoPermission, NoType,
		},
		{"test for secret zero create timestamp",
			&pbauth.Identification{
				Token: valid512JWTAdminTokenString,
				Secret: &pbauth.Secret{
					Key: validSecretKey,
				},
			}, true, consts.ErrInvalidSecretCreateTimestamp, NoPermission, NoType,
		},
		{"test for secret create timestamp after now",
			&pbauth.Identification{
				Token: valid512JWTAdminTokenString,
				Secret: &pbauth.Secret{
					Key:              validSecretKey,
					CreatedTimestamp: time.Now().UTC().Unix() + 60,
				},
			}, true, consts.ErrInvalidSecretCreateTimestamp, NoPermission, NoType,
		},
		{"test for secret zero expiration timestamp",
			&pbauth.Identification{
				Token: valid512JWTAdminTokenString,
				Secret: &pbauth.Secret{
					Key:              validSecretKey,
					CreatedTimestamp: validCreatedTimestamp,
				},
			}, true, consts.ErrExpiredSecret, NoPermission, NoType,
		},
		{"test for expired secret",
			&pbauth.Identification{
				Token: valid512JWTAdminTokenString,
				Secret: &pbauth.Secret{
					Key:                 validSecretKey,
					CreatedTimestamp:    validCreatedTimestamp,
					ExpirationTimestamp: time.Now().UTC().Unix() - 60,
				},
			}, true, consts.ErrExpiredSecret, NoPermission, NoType,
		},
		{"test for invalid permission: token with user perm versus admin required authorization",
			&pbauth.Identification{
				Token:  valid256JWTUserTokenString,
				Secret: validSecret,
			}, true, consts.ErrInvalidPermission, Admin, NoType,
		},
		{"test for token with admin perm versus user required authorization",
			&pbauth.Identification{
				Token:  valid512JWTAdminTokenString,
				Secret: validSecret,
			}, false, nil, User, Jwt,
		},
		{"test for token with no type versus jwt required token type",
			&pbauth.Identification{
				Token:  invalid256NoTypeTokenString,
				Secret: validSecret,
			}, true, consts.ErrInvalidRequiredTokenType, User, Jwt,
		},
		{"test for invalid token string",
			&pbauth.Identification{
				Token:  "a.b",
				Secret: validSecret,
			}, true, consts.ErrIncompleteToken, User, Jwt,
		},
		{"test with invalid token of HS256 with Admin permission",
			&pbauth.Identification{
				Token:  invalid256JWTTokenString,
				Secret: validSecret,
			}, true, consts.ErrInvalidPermission, User, Jwt,
		},
		{"test with valid user token",
			&pbauth.Identification{
				Token:  valid256JWTUserTokenString,
				Secret: validSecret,
			}, false, nil, User, Jwt,
		},
	}
	for _, c := range cases {
		a := NewAuthority(c.requiredToken, c.requiredPerm)
		assert.Equal(t, c.requiredPerm, a.permissionRequired, c.desc)
		err := a.Authorize(c.id)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error(), c.desc)
		} else {
			assert.Nil(t, err, c.desc)
		}
	}
	a := Authority{}
	err := a.Authorize(nil)
	assert.EqualError(t, err, consts.ErrNilIdentification.Error(), "test for nil identification")
}

func TestBody(t *testing.T) {
	cases := []struct {
		desc          string
		id            *pbauth.Identification
		isExpErr      bool
		expErr        error
		requiredPerm  Permission
		requiredToken TokenType
	}{
		{"test for valid admin token",
			&pbauth.Identification{
				Token:  valid512JWTAdminTokenString,
				Secret: validSecret,
			}, false, nil, User, Jwt,
		},
		{"test for valid user token",
			&pbauth.Identification{
				Token:  valid256JWTUserTokenString,
				Secret: validSecret,
			}, false, nil, User, Jwt,
		},
	}
	for _, c := range cases {
		a := NewAuthority(c.requiredToken, c.requiredPerm)
		assert.Equal(t, c.requiredPerm, a.permissionRequired, c.desc)
		err := a.Authorize(c.id)
		assert.Nil(t, err)
		copiedBody := a.Body()
		assert.Equal(t, a.body.UUID, copiedBody.UUID, c.desc)
		assert.Equal(t, a.body.Permission, copiedBody.Permission, c.desc)
		assert.Equal(t, a.body.ExpirationTimestamp, copiedBody.ExpirationTimestamp, c.desc)
		copiedBody.UUID = "mutate"
		assert.NotEqual(t, a.body.UUID, copiedBody.UUID, c.desc)
	}
}

func TestInvalidate(t *testing.T) {
	cases := []struct {
		desc          string
		id            *pbauth.Identification
		requiredPerm  Permission
		requiredToken TokenType
	}{
		{"test for valid admin token",
			&pbauth.Identification{
				Token:  valid512JWTAdminTokenString,
				Secret: validSecret,
			}, User, Jwt,
		},
		{"test for valid user token",
			&pbauth.Identification{
				Token:  valid256JWTUserTokenString,
				Secret: validSecret,
			}, User, Jwt,
		},
	}
	for _, c := range cases {
		a := NewAuthority(c.requiredToken, c.requiredPerm)
		assert.Equal(t, c.requiredPerm, a.permissionRequired, c.desc)
		err := a.Authorize(c.id)
		assert.Nil(t, err)
		a.Invalidate()
		assert.Nil(t, a.id, c.desc)
		assert.Nil(t, a.header, c.desc)
		assert.Nil(t, a.body, c.desc)
		assert.Equal(t, NoType, a.tokenRequired, c.desc)
		assert.Equal(t, NoPermission, a.permissionRequired, c.desc)
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		desc      string
		authority *Authority
		isExpErr  bool
		expErr    error
	}{
		{"test for nil identification", &Authority{}, true, consts.ErrNilIdentification},
		{"test for empty token string",
			&Authority{
				id: &pbauth.Identification{},
			}, true, consts.ErrEmptyToken,
		},
		{"test for nil secret",
			&Authority{
				id: &pbauth.Identification{
					Token: valid256JWTUserTokenString,
				},
			}, true, consts.ErrNilSecret,
		},
		{"test for empty secret key",
			&Authority{
				id: &pbauth.Identification{
					Token:  valid256JWTUserTokenString,
					Secret: &pbauth.Secret{},
				},
			}, true, consts.ErrEmptySecret,
		},
		{"test for secret zero create timestamp",
			&Authority{
				id: &pbauth.Identification{
					Token: valid256JWTUserTokenString,
					Secret: &pbauth.Secret{
						Key: validSecretKey,
					},
				},
			}, true, consts.ErrInvalidSecretCreateTimestamp,
		},
		{"test for secret create timestamp after now",
			&Authority{
				id: &pbauth.Identification{
					Token: valid256JWTUserTokenString,
					Secret: &pbauth.Secret{
						Key:              validSecretKey,
						CreatedTimestamp: time.Now().UTC().Unix() + 60,
					},
				},
			}, true, consts.ErrInvalidSecretCreateTimestamp,
		},
		{"test for secret zero expiration timestamp",
			&Authority{
				id: &pbauth.Identification{
					Token: valid256JWTUserTokenString,
					Secret: &pbauth.Secret{
						Key:              validSecretKey,
						CreatedTimestamp: validCreatedTimestamp,
					},
				},
			}, true, consts.ErrExpiredSecret,
		},
		{"test for expired secret",
			&Authority{
				id: &pbauth.Identification{
					Token: valid256JWTUserTokenString,
					Secret: &pbauth.Secret{
						Key:                 validSecretKey,
						CreatedTimestamp:    validCreatedTimestamp,
						ExpirationTimestamp: time.Now().UTC().Unix() - 60,
					},
				},
			}, true, consts.ErrExpiredSecret,
		},
		{"test for invalid token string",
			&Authority{
				id: &pbauth.Identification{
					Token:  "a.b",
					Secret: validSecret,
				},
			}, true, consts.ErrIncompleteToken,
		},
		{"test for invalid json marshal/unmarshal",
			&Authority{
				header: &Header{},
				id: &pbauth.Identification{
					Token:  "eyJBbGciOjEsIlRva2VuVHlwIjowfQas.b.c",
					Secret: validSecret,
				},
			}, true, errors.New("invalid character '\\x06' after top-level value"),
		},
		{"test for invalid single byte json marshal/unmarshal",
			&Authority{
				id: &pbauth.Identification{
					Token:  "a.b.c",
					Secret: validSecret,
				},
			}, true, errors.New("decoding error illegal base64 data at input byte 1"),
		},
		{"test for mismatched required token type from tokenRequired and Token",
			&Authority{
				header: &Header{},
				body:   &Body{},
				id: &pbauth.Identification{
					Token:  valid256JWTUserTokenString,
					Secret: validSecret,
				},
			}, true, consts.ErrInvalidRequiredTokenType,
		},
		{"test for mismatched required token type from tokenRequired and Token",
			&Authority{
				header:        &Header{},
				body:          &Body{},
				tokenRequired: Jwt,
				id: &pbauth.Identification{
					Token:  invalid256NoTypeTokenString,
					Secret: validSecret,
				},
			}, true, consts.ErrInvalidRequiredTokenType,
		},
		{"test for permission required of Admin versus User token",
			&Authority{
				header:             &Header{},
				body:               &Body{},
				tokenRequired:      Jwt,
				permissionRequired: Admin,
				id: &pbauth.Identification{
					Token:  valid256JWTUserTokenString,
					Secret: validSecret,
				},
			}, true, consts.ErrInvalidPermission,
		},
		{"test for HS256 with Admin permission",
			&Authority{
				header:             &Header{},
				body:               &Body{},
				tokenRequired:      Jwt,
				permissionRequired: Admin,
				id: &pbauth.Identification{
					Token:  invalid256JWTTokenString,
					Secret: validSecret,
				},
			}, true, consts.ErrInvalidPermission,
		},
		{"test for invalid user UUID",
			&Authority{
				header:             &Header{},
				body:               &Body{},
				tokenRequired:      Jwt,
				permissionRequired: Admin,
				id: &pbauth.Identification{
					Token:  invalidUUIDUserToken,
					Secret: validSecret,
				},
			}, true, consts.ErrInvalidUUID,
		},
		{"test for expired user token",
			&Authority{
				header:             &Header{},
				body:               &Body{},
				tokenRequired:      Jwt,
				permissionRequired: Admin,
				id: &pbauth.Identification{
					Token:  expiredUserToken,
					Secret: validSecret,
				},
			}, true, consts.ErrExpiredBody,
		},
		{"test for fake token",
			&Authority{
				header:             &Header{},
				body:               &Body{},
				tokenRequired:      Jwt,
				permissionRequired: User,
				id: &pbauth.Identification{
					Token:  fakeToken,
					Secret: validSecret,
				},
			}, true, consts.ErrInvalidSignature,
		},
		{"test for valid admin token versus admin permission requirement",
			&Authority{
				header:             &Header{},
				body:               &Body{},
				tokenRequired:      Jwt,
				permissionRequired: Admin,
				id: &pbauth.Identification{
					Token:  valid512JWTAdminTokenString,
					Secret: validSecret,
				},
			}, false, nil,
		},
		{"test for valid admin token versus user permission requirement",
			&Authority{
				header:             &Header{},
				body:               &Body{},
				tokenRequired:      Jwt,
				permissionRequired: User,
				id: &pbauth.Identification{
					Token:  valid512JWTAdminTokenString,
					Secret: validSecret,
				},
			}, false, nil,
		},
		{"test for valid user token versus user permission requirement",
			&Authority{
				header:             &Header{},
				body:               &Body{},
				tokenRequired:      Jwt,
				permissionRequired: User,
				id: &pbauth.Identification{
					Token:  valid256JWTUserTokenString,
					Secret: validSecret,
				},
			}, false, nil,
		},
		{"test for invalid header with unknown algorithm",
			&Authority{
				header:             &Header{},
				body:               &Body{},
				tokenRequired:      Jwt,
				permissionRequired: User,
				id: &pbauth.Identification{
					Token:  unknownAlgToken,
					Secret: validSecret,
				},
			}, true, consts.ErrUnknownAlgorithm,
		},
	}
	for _, c := range cases {
		err := c.authority.Validate()
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error(), c.desc)
		} else {
			assert.Nil(t, err, c.desc)
		}
	}
}

func TestHasExpired(t *testing.T) {
	cases := []struct {
		desc      string
		authority *Authority
		expOut    bool
	}{
		{"test for nil header",
			&Authority{
				body:               &Body{},
				tokenRequired:      Jwt,
				permissionRequired: Admin,
				id: &pbauth.Identification{
					Token:  valid512JWTAdminTokenString,
					Secret: validSecret,
				},
			}, true,
		},
		{"test for nil body",
			&Authority{
				header:             &Header{},
				tokenRequired:      Jwt,
				permissionRequired: Admin,
				id: &pbauth.Identification{
					Token:  valid512JWTAdminTokenString,
					Secret: validSecret,
				},
			}, true,
		},
		{"test for nil identification",
			&Authority{
				header:             &Header{},
				body:               validAdminBody,
				tokenRequired:      Jwt,
				permissionRequired: Admin,
			}, true,
		},
		{"test for expired user token",
			&Authority{
				header:             &Header{},
				body:               &Body{},
				tokenRequired:      Jwt,
				permissionRequired: Admin,
				id: &pbauth.Identification{
					Token:  expiredUserToken,
					Secret: validSecret,
				},
			}, true,
		},
		{"test for invalid user UUID in body",
			&Authority{
				header:             &Header{},
				body:               &Body{},
				tokenRequired:      Jwt,
				permissionRequired: Admin,
				id: &pbauth.Identification{
					Token:  valid512JWTAdminTokenString,
					Secret: validSecret,
				},
			}, true,
		},
		{"test for valid user token",
			&Authority{
				header:             valid256JWT,
				body:               validUserBody,
				tokenRequired:      Jwt,
				permissionRequired: User,
				id: &pbauth.Identification{
					Token:  valid256JWTUserTokenString,
					Secret: validSecret,
				},
			}, false,
		},
		{"test for valid admin token",
			&Authority{
				header:             valid512JWT,
				body:               validAdminBody,
				tokenRequired:      Jwt,
				permissionRequired: Admin,
				id: &pbauth.Identification{
					Token:  valid512JWTAdminTokenString,
					Secret: validSecret,
				},
			}, false,
		},
	}
	for _, c := range cases {
		actOutput := c.authority.HasExpired()
		assert.Equal(t, c.expOut, actOutput, c.desc)

	}

}
