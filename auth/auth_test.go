package auth

import (
	"errors"
	pbauth "github.com/hwsc-org/hwsc-api-blocks/lib"
	"github.com/hwsc-org/hwsc-lib/consts"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestNewAuthority(t *testing.T) {
	cases := []struct {
		requiredToken TokenType
		expToken      TokenType
		requiredPerm  Permission
		expPermLevel  Permission
	}{
		{NoType - 1, NoType, -1, NoPermission},
		{Jwt + 1, NoType, -1, NoPermission},
		{NoType, NoType, NoPermission - 1, NoPermission},
		{Jwt, Jwt, -1, NoPermission},
		{NoType, NoType, NoPermission, NoPermission},
		{NoType, NoType, UserRegistration, UserRegistration},
		{NoType, NoType, User, User},
		{NoType, NoType, Admin, Admin},
		{NoType, NoType, Admin + 1, NoPermission},
	}
	for _, c := range cases {
		a := NewAuthority(c.requiredToken, c.requiredPerm)
		assert.Equal(t, c.expPermLevel, a.permissionRequired)
		assert.Equal(t, c.expToken, a.tokenRequired)
	}
}

func TestAuthorize(t *testing.T) {
	cases := []struct {
		id            *pbauth.Identification
		isExpErr      bool
		expErr        error
		requiredPerm  Permission
		requiredToken TokenType
	}{
		{nil, true, consts.ErrNilIdentification, NoPermission, NoType},
		{&pbauth.Identification{}, true, consts.ErrEmptyToken, NoPermission, NoType},
		{
			&pbauth.Identification{
				Token: valid512JWTAdminTokenString,
			}, true, consts.ErrNilSecret, NoPermission, NoType,
		},
		{
			&pbauth.Identification{
				Token:  valid512JWTAdminTokenString,
				Secret: &pbauth.Secret{},
			}, true, consts.ErrEmptySecret, NoPermission, NoType,
		},
		{
			&pbauth.Identification{
				Token: valid512JWTAdminTokenString,
				Secret: &pbauth.Secret{
					Key: validSecretKey,
				},
			}, true, consts.ErrInvalidSecretCreateTimestamp, NoPermission, NoType,
		},
		{
			&pbauth.Identification{
				Token: valid512JWTAdminTokenString,
				Secret: &pbauth.Secret{
					Key:              validSecretKey,
					CreatedTimestamp: time.Now().UTC().Unix() + 60,
				},
			}, true, consts.ErrInvalidSecretCreateTimestamp, NoPermission, NoType,
		},
		{
			&pbauth.Identification{
				Token: valid512JWTAdminTokenString,
				Secret: &pbauth.Secret{
					Key:              validSecretKey,
					CreatedTimestamp: validCreatedTimestamp,
				},
			}, true, consts.ErrExpiredSecret, NoPermission, NoType,
		},
		{
			&pbauth.Identification{
				Token: valid512JWTAdminTokenString,
				Secret: &pbauth.Secret{
					Key:                 validSecretKey,
					CreatedTimestamp:    validCreatedTimestamp,
					ExpirationTimestamp: time.Now().UTC().Unix() - 60,
				},
			}, true, consts.ErrExpiredSecret, NoPermission, NoType,
		},
		{
			&pbauth.Identification{
				Token:  valid256JWTUserTokenString,
				Secret: validSecret,
			}, true, consts.ErrInvalidPermission, Admin, NoType,
		},
		{
			&pbauth.Identification{
				Token:  valid512JWTAdminTokenString,
				Secret: validSecret,
			}, false, nil, User, Jwt,
		},
		{
			&pbauth.Identification{
				Token:  invalid256NoTypeTokenString,
				Secret: validSecret,
			}, true, consts.ErrInvalidRequiredTokenType, User, Jwt,
		},
		{
			&pbauth.Identification{
				Token:  "a.b",
				Secret: validSecret,
			}, true, consts.ErrIncompleteToken, User, Jwt,
		},
		{
			&pbauth.Identification{
				Token:  invalid256JWTTokenString,
				Secret: validSecret,
			}, true, consts.ErrInvalidPermission, User, Jwt,
		},
		{
			&pbauth.Identification{
				Token:  valid256JWTUserTokenString,
				Secret: validSecret,
			}, false, nil, User, Jwt,
		},
	}
	for _, c := range cases {
		a := NewAuthority(c.requiredToken, c.requiredPerm)
		assert.Equal(t, c.requiredPerm, a.permissionRequired)
		err := a.Authorize(c.id)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error())
		} else {
			assert.Nil(t, err)
		}
	}
	a := Authority{}
	err := a.Authorize(nil)
	assert.EqualError(t, err, consts.ErrNilIdentification.Error())
}

func TestInvalidate(t *testing.T) {
	cases := []struct {
		id            *pbauth.Identification
		isExpErr      bool
		expErr        error
		requiredPerm  Permission
		requiredToken TokenType
	}{
		{
			&pbauth.Identification{
				Token:  valid512JWTAdminTokenString,
				Secret: validSecret,
			}, false, nil, User, Jwt,
		},
		{
			&pbauth.Identification{
				Token:  valid256JWTUserTokenString,
				Secret: validSecret,
			}, false, nil, User, Jwt,
		},
	}
	for _, c := range cases {
		a := NewAuthority(c.requiredToken, c.requiredPerm)
		assert.Equal(t, c.requiredPerm, a.permissionRequired)
		a.Invalidate()
		assert.Nil(t, a.id)
		assert.Nil(t, a.header)
		assert.Nil(t, a.body)
		assert.Equal(t, NoType, a.tokenRequired)
		assert.Equal(t, NoPermission, a.permissionRequired)
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		authority *Authority
		isExpErr  bool
		expErr    error
	}{
		{&Authority{}, true, consts.ErrNilIdentification},
		{
			&Authority{
				id: &pbauth.Identification{},
			}, true, consts.ErrEmptyToken,
		},
		{
			&Authority{
				id: &pbauth.Identification{
					Token: valid256JWTUserTokenString,
				},
			}, true, consts.ErrNilSecret,
		},
		{
			&Authority{
				id: &pbauth.Identification{
					Token:  valid256JWTUserTokenString,
					Secret: &pbauth.Secret{},
				},
			}, true, consts.ErrEmptySecret,
		},
		{
			&Authority{
				id: &pbauth.Identification{
					Token: valid256JWTUserTokenString,
					Secret: &pbauth.Secret{
						Key: validSecretKey,
					},
				},
			}, true, consts.ErrInvalidSecretCreateTimestamp,
		},
		{
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
		{
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
		{
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
		{
			&Authority{
				id: &pbauth.Identification{
					Token:  "a.b",
					Secret: validSecret,
				},
			}, true, consts.ErrIncompleteToken,
		},
		{
			&Authority{
				header: &Header{},
				id: &pbauth.Identification{
					Token:  "eyJBbGciOjEsIlRva2VuVHlwIjowfQas.b.c",
					Secret: validSecret,
				},
			}, true, errors.New("invalid character '\\x06' after top-level value"),
		},
		{
			&Authority{
				id: &pbauth.Identification{
					Token:  "a.b.c",
					Secret: validSecret,
				},
			}, true, errors.New("decoding error illegal base64 data at input byte 1"),
		},
		{
			&Authority{
				header: &Header{},
				body:   &Body{},
				id: &pbauth.Identification{
					Token:  valid256JWTUserTokenString,
					Secret: validSecret,
				},
			}, true, consts.ErrInvalidRequiredTokenType,
		},
		{
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
		{
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
		{
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
		{
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
		{
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
		{
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
		{
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
		{
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
		{
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
	}
	for _, c := range cases {
		err := c.authority.Validate()
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error())
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestHasExpired(t *testing.T) {
	cases := []struct {
		authority *Authority
		expOut    bool
	}{
		{
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
		{
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
		{
			&Authority{
				header:             &Header{},
				body:               &Body{},
				tokenRequired:      Jwt,
				permissionRequired: Admin,
				id: &pbauth.Identification{
					Token:  invalidUUIDUserToken,
					Secret: validSecret,
				},
			}, true,
		},
		{
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
		{
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
		{
			&Authority{
				header:             valid256JWT,
				body:               &Body{},
				tokenRequired:      Jwt,
				permissionRequired: Admin,
				id: &pbauth.Identification{
					Token:  valid256JWTUserTokenString,
					Secret: validSecret,
				},
			}, true,
		},
		{
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
		{
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
		assert.Equal(t, c.expOut, actOutput)

	}

}
