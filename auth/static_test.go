package auth

import (
	"encoding/json"
	pbauth "github.com/hwsc-org/hwsc-api-blocks/lib"
	"github.com/hwsc-org/hwsc-lib/consts"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestValidateIdentification(t *testing.T) {
	cases := []struct {
		input    *pbauth.Identification
		isExpErr bool
		expErr   error
	}{
		{nil, true, consts.ErrNilIdentification},
		{&pbauth.Identification{}, true, consts.ErrEmptyToken},
		{
			&pbauth.Identification{
				Token: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1dWlkIjoiMTIzNDU2Nzg5MCIsInBlcm1pc3Npb24iOiJUb2tlbi5BRE1JTiIsImV4cGlyYXRpb25fdGltZSI6MTU0OTA5MzkxMH0.OZFQ_zU1F2BJm6kyYzsBns5qmOxbVbUnQV2SU1B_kyPfXPOmUd0fddRvF0I3IqaDz-55H7Q80w8zQyldMQ7AAg",
			}, true, consts.ErrNilSecret,
		},
		{
			&pbauth.Identification{
				Token: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1dWlkIjoiMTIzNDU2Nzg5MCIsInBlcm1pc3Npb24iOiJUb2tlbi5BRE1JTiIsImV4cGlyYXRpb25fdGltZSI6MTU0OTA5MzkxMH0.OZFQ_zU1F2BJm6kyYzsBns5qmOxbVbUnQV2SU1B_kyPfXPOmUd0fddRvF0I3IqaDz-55H7Q80w8zQyldMQ7AAg",
				Secret: &pbauth.Secret{
					Key: "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				},
			}, true, consts.ErrInvalidSecretCreateTimestamp,
		},
		{
			&pbauth.Identification{
				Token: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1dWlkIjoiMTIzNDU2Nzg5MCIsInBlcm1pc3Npb24iOiJUb2tlbi5BRE1JTiIsImV4cGlyYXRpb25fdGltZSI6MTU0OTA5MzkxMH0.OZFQ_zU1F2BJm6kyYzsBns5qmOxbVbUnQV2SU1B_kyPfXPOmUd0fddRvF0I3IqaDz-55H7Q80w8zQyldMQ7AAg",
				Secret: &pbauth.Secret{
					Key:              "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
					CreatedTimestamp: time.Now().UTC().Unix() + 1,
				},
			}, true, consts.ErrInvalidSecretCreateTimestamp,
		},
		{
			&pbauth.Identification{
				Token: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1dWlkIjoiMTIzNDU2Nzg5MCIsInBlcm1pc3Npb24iOiJUb2tlbi5BRE1JTiIsImV4cGlyYXRpb25fdGltZSI6MTU0OTA5MzkxMH0.OZFQ_zU1F2BJm6kyYzsBns5qmOxbVbUnQV2SU1B_kyPfXPOmUd0fddRvF0I3IqaDz-55H7Q80w8zQyldMQ7AAg",
				Secret: &pbauth.Secret{
					Key:              "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
					CreatedTimestamp: validCreatedTimestamp,
				},
			}, true, consts.ErrExpiredSecret,
		},
		{
			&pbauth.Identification{
				Token:  "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1dWlkIjoiMTIzNDU2Nzg5MCIsInBlcm1pc3Npb24iOiJUb2tlbi5BRE1JTiIsImV4cGlyYXRpb25fdGltZSI6MTU0OTA5MzkxMH0.OZFQ_zU1F2BJm6kyYzsBns5qmOxbVbUnQV2SU1B_kyPfXPOmUd0fddRvF0I3IqaDz-55H7Q80w8zQyldMQ7AAg",
				Secret: validSecret,
			}, false, nil,
		},
	}

	for _, c := range cases {
		err := ValidateIdentification(c.input)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error())
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestValidateHeader(t *testing.T) {
	cases := []struct {
		input    *Header
		isExpErr bool
		expErr   error
	}{
		{nil, true, consts.ErrNilHeader},
		{valid256JWT, false, nil},
		{valid512JWT, false, nil},
	}
	for _, c := range cases {
		err := ValidateHeader(c.input)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error())
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestValidateBody(t *testing.T) {
	cases := []struct {
		input    *Body
		isExpErr bool
		expErr   error
	}{
		{nil, true, consts.ErrNilBody},
		{&Body{}, true, consts.ErrInvalidUUID},
		{&Body{UUID: "01d3x3wm2nnrdfzp0tka2vw9dx"}, true, consts.ErrExpiredBody},
		{validAdminBody, false, nil},
	}
	for _, c := range cases {
		err := ValidateBody(c.input)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error())
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestValidateSecret(t *testing.T) {
	cases := []struct {
		input    *pbauth.Secret
		isExpErr bool
		expErr   error
	}{
		{nil, true, consts.ErrNilSecret},
		{
			&pbauth.Secret{
				Key: "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
			}, true, consts.ErrInvalidSecretCreateTimestamp,
		},
		{
			&pbauth.Secret{
				Key:              "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				CreatedTimestamp: validCreatedTimestamp,
			}, true, consts.ErrExpiredSecret,
		},
		{
			&pbauth.Secret{
				Key:              "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				CreatedTimestamp: time.Now().UTC().Unix() + 60,
			}, true, consts.ErrInvalidSecretCreateTimestamp,
		},
		{validSecret, false, nil},
	}
	for _, c := range cases {
		err := ValidateSecret(c.input)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error())
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestIsExpired(t *testing.T) {
	cases := []struct {
		input     int64
		expOutput bool
	}{
		{0, true},
		{time.Now().UTC().Unix() - 60, true},
		{time.Now().UTC().Unix() + 60, false},
	}
	for _, c := range cases {
		actOuput := isExpired(c.input)
		assert.Equal(t, c.expOutput, actOuput)
	}
}

func TestNewToken(t *testing.T) {
	cases := []struct {
		header    *Header
		body      *Body
		secret    *pbauth.Secret
		isExpErr  bool
		expErr    error
		expOutput string
	}{
		{nil, nil, nil, true, consts.ErrNilHeader, ""},
		{valid256JWT, nil, nil, true, consts.ErrNilBody, ""},
		{valid512JWT, nil, nil, true, consts.ErrNilBody, ""},
		{valid512JWT, &Body{}, nil, true, consts.ErrInvalidUUID, ""},
		{valid512JWT, &Body{UUID: "01d3x3wm2nnrdfzp0tka2vw9dx"}, nil, true, consts.ErrExpiredBody, ""},
		{valid512JWT, validAdminBody, nil, true, consts.ErrNilSecret, ""},
		{valid512JWT, validAdminBody,
			&pbauth.Secret{
				Key: "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
			},
			true, consts.ErrInvalidSecretCreateTimestamp, "",
		},
		{valid512JWT, validAdminBody,
			&pbauth.Secret{
				Key:              "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				CreatedTimestamp: time.Now().UTC().Unix() + 1,
			},
			true, consts.ErrInvalidSecretCreateTimestamp, "",
		},
		{valid512JWT, validAdminBody,
			&pbauth.Secret{
				Key:              "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				CreatedTimestamp: validCreatedTimestamp,
			},
			true, consts.ErrExpiredSecret, "",
		},
		{valid512JWT, validAdminBody, validSecret, false, nil, valid512JWTAdminTokenString},
		{valid256JWT, validAdminBody, validSecret, true, consts.ErrInvalidPermission, ""},
		{valid256NoType, validUserBody, validSecret, true, consts.ErrInvalidJWT, ""},
		{valid256JWT, validUserBody, validSecret, false, nil, valid256JWTUserTokenString},
		{valid256JWT, expiredUserBody, validSecret, true, consts.ErrExpiredBody, ""},
	}
	for _, c := range cases {
		output, err := NewToken(c.header, c.body, c.secret)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error())
		} else {
			assert.Nil(t, err)
			assert.Equal(t, c.expOutput, output)
		}
	}
}

func TestGetTokenSignature(t *testing.T) {
	cases := []struct {
		header    *Header
		body      *Body
		secret    *pbauth.Secret
		isExpErr  bool
		expErr    error
		expOutput string
	}{
		{nil, nil, nil, true, consts.ErrNilHeader, ""},
		{valid256JWT, nil, nil, true, consts.ErrNilBody, ""},
		{valid512JWT, nil, nil, true, consts.ErrNilBody, ""},
		{valid512JWT, &Body{}, nil, true, consts.ErrInvalidUUID, ""},
		{
			valid512JWT,
			&Body{UUID: "01d3x3wm2nnrdfzp0tka2vw9dx"},
			nil, true, consts.ErrExpiredBody, "",
		},
		{valid512JWT, validAdminBody, nil, true, consts.ErrNilSecret, ""},
		{valid512JWT, validAdminBody,
			&pbauth.Secret{
				Key: "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
			},
			true, consts.ErrInvalidSecretCreateTimestamp, ",",
		},
		{valid512JWT, validAdminBody,
			&pbauth.Secret{
				Key:              "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				CreatedTimestamp: time.Now().UTC().Unix() + 1,
			},
			true, consts.ErrInvalidSecretCreateTimestamp, "",
		},
		{valid512JWT, validAdminBody,
			&pbauth.Secret{
				Key:              "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				CreatedTimestamp: validCreatedTimestamp,
			},
			true, consts.ErrExpiredSecret, "",
		},
		{valid512JWT, validAdminBody, validSecret, false, nil, valid512JWTAdminTokenString},
		{valid256JWT, validAdminBody, validSecret, true, consts.ErrInvalidPermission, ""},
		{valid256NoType, validUserBody, validSecret, true, consts.ErrInvalidJWT, ""},
		{valid256JWT, validUserBody, validSecret, false, nil, valid256JWTUserTokenString},
		{valid256JWT, expiredUserBody, validSecret, true, consts.ErrExpiredBody, ""},
	}
	for _, c := range cases {
		output, err := getTokenSignature(c.header, c.body, c.secret)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error())
		} else {
			assert.Nil(t, err)
			assert.Equal(t, c.expOutput, output)
		}
	}
}

func TestBuildTokenSignature(t *testing.T) {
	cases := []struct {
		header    string
		body      string
		alg       Algorithm
		secret    *pbauth.Secret
		isExpErr  bool
		expErr    error
		expOutput string
	}{
		{"", "", NoAlg, nil, true, consts.ErrInvalidEncodedHeader, ""},
		{encoded256JWTHeader, "", NoAlg, nil, true, consts.ErrInvalidEncodedBody, ""},
		{encoded512JWTHeader, "", NoAlg, nil, true, consts.ErrInvalidEncodedBody, ""},
		{encoded256JWTHeader, encodedAdminBody, NoAlg, nil, true, consts.ErrNilSecret, ""},
		{encoded512JWTHeader, encodedAdminBody, Hs512, validSecret, false, nil, valid512JWTAdminTokenString},
		{encoded256JWTHeader, encodedUserBody, Hs256, validSecret, false, nil, valid256JWTUserTokenString},
	}
	for _, c := range cases {
		actOutput, err := buildTokenSignature(c.header, c.body, c.alg, c.secret)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error())
		} else {
			assert.Equal(t, c.expOutput, actOutput)
		}
	}
}

func TestBase64Encode(t *testing.T) {
	cases := []struct {
		input     interface{}
		isExpErr  bool
		expErr    error
		expOutput string
	}{
		{nil, true, consts.ErrNilInterface, ""},
		{valid256JWT, false, nil, encoded256JWTHeader},
		{valid512JWT, false, nil, encoded512JWTHeader},
		{validAdminBody, false, nil, encodedAdminBody},
		{validUserBody, false, nil, encodedUserBody},
	}
	for _, c := range cases {
		output, err := base64Encode(c.input)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error())
		} else {
			assert.Nil(t, err)
			assert.Equal(t, c.expOutput, output)
		}
	}
}

func TestBase64Decode(t *testing.T) {
	cases := []struct {
		input      string
		isExpErr   bool
		expErr     error
		expOutput  interface{}
		structType int
	}{
		{"", true, consts.ErrEmptyString, nil, 0},
		{encoded256JWTHeader, false, nil, valid256JWT, 0},
		{encoded512JWTHeader, false, nil, valid512JWT, 0},
		{encodedAdminBody, false, nil, validAdminBody, 1},
		{encodedUserBody, false, nil, validUserBody, 1},
	}
	for _, c := range cases {
		output, err := base64Decode(c.input)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error())
		} else {
			assert.Nil(t, err)
			switch c.structType {
			case structHeader:
				var o *Header
				err := json.Unmarshal([]byte(output), &o)
				assert.Nil(t, err)
				assert.Equal(t, o, c.expOutput)
			case structBody:
				var o *Body
				err := json.Unmarshal([]byte(output), &o)
				assert.Nil(t, err)
				assert.Equal(t, o, c.expOutput)
			}
		}
	}
}

func TestHashSignature(t *testing.T) {
	cases := []struct {
		alg            Algorithm
		signatureValue string
		secret         *pbauth.Secret
		isExpErr       bool
		expErr         error
		expOutput      string
	}{
		{NoAlg, "", nil, true, consts.ErrInvalidSignatureValue, ""},
		{Hs512, valid512JWTAdminSignature, nil, true, consts.ErrNilSecret, ""},
		{Hs512, valid512JWTAdminSignature, validSecret, false, nil, valid512JWTAdminHAS},
		{Hs256, valid256JWTUserSignature, validSecret, false, nil, valid256JWTUserHAS},
		{NoAlg, valid256JWTUserSignature, validSecret, true, consts.ErrNoHashAlgorithm, ""},
	}
	for _, c := range cases {
		actOuput, err := hashSignature(c.alg, c.signatureValue, c.secret)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error())
		} else {
			assert.Nil(t, err)
			assert.Equal(t, c.expOutput, actOuput)
		}
	}
}

func TestIsEquivalentHash(t *testing.T) {
	cases := []struct {
		alg            Algorithm
		signatureValue string
		secret         *pbauth.Secret
		hashedValue    string
		expOutput      bool
	}{
		{Hs512, valid512JWTAdminSignature, nil, "", false},
		{Hs512, valid512JWTAdminSignature, validSecret, valid512JWTAdminHAS, true},
		{Hs256, valid256JWTUserSignature, validSecret, valid256JWTUserHAS, true},
	}
	for _, c := range cases {
		actOuput := isEquivalentHash(c.alg, c.signatureValue, c.secret, c.hashedValue)
		assert.Equal(t, c.expOutput, actOuput)
	}
}
