package auth

import (
	"encoding/json"
	pbauth "github.com/hwsc-org/hwsc-api-blocks/protobuf/lib"
	"github.com/hwsc-org/hwsc-lib/consts"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestValidateIdentification(t *testing.T) {
	cases := []struct {
		desc     string
		input    *pbauth.Identification
		isExpErr bool
		expErr   error
	}{
		{"test nil identification", nil, true, consts.ErrNilIdentification},
		{"test empty token string", &pbauth.Identification{}, true, consts.ErrEmptyToken},
		{"test nil secret",
			&pbauth.Identification{
				Token: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1dWlkIjoiMTIzNDU2Nzg5MCIsInBlcm1pc3Npb24iOiJUb2tlbi5BRE1JTiIsImV4cGlyYXRpb25fdGltZSI6MTU0OTA5MzkxMH0.OZFQ_zU1F2BJm6kyYzsBns5qmOxbVbUnQV2SU1B_kyPfXPOmUd0fddRvF0I3IqaDz-55H7Q80w8zQyldMQ7AAg",
			}, true, consts.ErrNilSecret,
		},
		{"test for secret zero create timestamp",
			&pbauth.Identification{
				Token: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1dWlkIjoiMTIzNDU2Nzg5MCIsInBlcm1pc3Npb24iOiJUb2tlbi5BRE1JTiIsImV4cGlyYXRpb25fdGltZSI6MTU0OTA5MzkxMH0.OZFQ_zU1F2BJm6kyYzsBns5qmOxbVbUnQV2SU1B_kyPfXPOmUd0fddRvF0I3IqaDz-55H7Q80w8zQyldMQ7AAg",
				Secret: &pbauth.Secret{
					Key: "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				},
			}, true, consts.ErrInvalidSecretCreateTimestamp,
		},
		{"test for secret create timestamp after now",
			&pbauth.Identification{
				Token: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1dWlkIjoiMTIzNDU2Nzg5MCIsInBlcm1pc3Npb24iOiJUb2tlbi5BRE1JTiIsImV4cGlyYXRpb25fdGltZSI6MTU0OTA5MzkxMH0.OZFQ_zU1F2BJm6kyYzsBns5qmOxbVbUnQV2SU1B_kyPfXPOmUd0fddRvF0I3IqaDz-55H7Q80w8zQyldMQ7AAg",
				Secret: &pbauth.Secret{
					Key:              "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
					CreatedTimestamp: time.Now().UTC().Unix() + 1,
				},
			}, true, consts.ErrInvalidSecretCreateTimestamp,
		},
		{"test for secret zero expiration timestamp",
			&pbauth.Identification{
				Token: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1dWlkIjoiMTIzNDU2Nzg5MCIsInBlcm1pc3Npb24iOiJUb2tlbi5BRE1JTiIsImV4cGlyYXRpb25fdGltZSI6MTU0OTA5MzkxMH0.OZFQ_zU1F2BJm6kyYzsBns5qmOxbVbUnQV2SU1B_kyPfXPOmUd0fddRvF0I3IqaDz-55H7Q80w8zQyldMQ7AAg",
				Secret: &pbauth.Secret{
					Key:              "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
					CreatedTimestamp: validCreatedTimestamp,
				},
			}, true, consts.ErrExpiredSecret,
		},
		{"test for expired secret",
			&pbauth.Identification{
				Token: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1dWlkIjoiMTIzNDU2Nzg5MCIsInBlcm1pc3Npb24iOiJUb2tlbi5BRE1JTiIsImV4cGlyYXRpb25fdGltZSI6MTU0OTA5MzkxMH0.OZFQ_zU1F2BJm6kyYzsBns5qmOxbVbUnQV2SU1B_kyPfXPOmUd0fddRvF0I3IqaDz-55H7Q80w8zQyldMQ7AAg",
				Secret: &pbauth.Secret{
					Key:                 "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
					CreatedTimestamp:    validCreatedTimestamp,
					ExpirationTimestamp: time.Now().UTC().Unix() - 60,
				},
			}, true, consts.ErrExpiredSecret,
		},
		{"test for valid input",
			&pbauth.Identification{
				Token:  "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1dWlkIjoiMTIzNDU2Nzg5MCIsInBlcm1pc3Npb24iOiJUb2tlbi5BRE1JTiIsImV4cGlyYXRpb25fdGltZSI6MTU0OTA5MzkxMH0.OZFQ_zU1F2BJm6kyYzsBns5qmOxbVbUnQV2SU1B_kyPfXPOmUd0fddRvF0I3IqaDz-55H7Q80w8zQyldMQ7AAg",
				Secret: validSecret,
			}, false, nil,
		},
	}

	for _, c := range cases {
		err := ValidateIdentification(c.input)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error(), c.desc)
		} else {
			assert.Nil(t, err, c.desc)
		}
	}
}

func TestValidateHeader(t *testing.T) {
	cases := []struct {
		desc     string
		input    *Header
		isExpErr bool
		expErr   error
	}{
		{"test for nil header", nil, true, consts.ErrNilHeader},
		{"test for negative token type",
			&Header{
				TokenTyp: NoType - 1,
			}, true, consts.ErrUnknownTokenType,
		},
		{"test for over token type",
			&Header{
				TokenTyp: Jet + 1,
			}, true, consts.ErrUnknownTokenType,
		},
		{"test for negative alg",
			&Header{
				Alg: NoAlg - 1,
			}, true, consts.ErrUnknownAlgorithm,
		},
		{"test for over alg",
			&Header{
				Alg: Hs512 + 1,
			}, true, consts.ErrUnknownAlgorithm,
		},
		{"test for valid 256 JWT header", valid256JWT, false, nil},
		{"test for valid 512 JWT header", valid512JWT, false, nil},
	}
	for _, c := range cases {
		err := ValidateHeader(c.input)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error(), c.desc)
		} else {
			assert.Nil(t, err, c.desc)
		}
	}
}

func TestValidateBody(t *testing.T) {
	cases := []struct {
		desc     string
		input    *Body
		isExpErr bool
		expErr   error
	}{
		{"test for nil body", nil, true, consts.ErrNilBody},
		{"test for invalid user UUID", &Body{}, true, consts.ErrInvalidUUID},
		{"test for body zero expiration timestamp",
			&Body{
				UUID: "01d3x3wm2nnrdfzp0tka2vw9dx",
			}, true, consts.ErrExpiredBody,
		},
		{"test for negative permission",
			&Body{
				UUID:       "01d3x3wm2nnrdfzp0tka2vw9dx",
				Permission: NoPermission - 1,
			}, true, consts.ErrUnknownPermission,
		},
		{"test for over permission",
			&Body{
				UUID:       "01d3x3wm2nnrdfzp0tka2vw9dx",
				Permission: Admin + 1,
			}, true, consts.ErrUnknownPermission,
		},
		{"test for expired token string",
			&Body{
				UUID:                "01d3x3wm2nnrdfzp0tka2vw9dx",
				ExpirationTimestamp: time.Now().UTC().Unix() - 60,
			}, true, consts.ErrExpiredBody,
		},
		{"test for valid input", validAdminBody, false, nil},
	}
	for _, c := range cases {
		err := ValidateBody(c.input)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error(), c.desc)
		} else {
			assert.Nil(t, err, c.desc)
		}
	}
}

func TestValidateSecret(t *testing.T) {
	cases := []struct {
		desc     string
		input    *pbauth.Secret
		isExpErr bool
		expErr   error
	}{
		{"test for nil secret", nil, true, consts.ErrNilSecret},
		{"test for secret zero create timestamp",
			&pbauth.Secret{
				Key: "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
			}, true, consts.ErrInvalidSecretCreateTimestamp,
		},
		{"test for secret zero expiration timestamp",
			&pbauth.Secret{
				Key:              "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				CreatedTimestamp: validCreatedTimestamp,
			}, true, consts.ErrExpiredSecret,
		},
		{"test for secret create timestamp after now",
			&pbauth.Secret{
				Key:              "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				CreatedTimestamp: time.Now().UTC().Unix() + 60,
			}, true, consts.ErrInvalidSecretCreateTimestamp,
		},
		{"test for valid input", validSecret, false, nil},
	}
	for _, c := range cases {
		err := ValidateSecret(c.input)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error(), c.desc)
		} else {
			assert.Nil(t, err, c.desc)
		}
	}
}

func TestIsExpired(t *testing.T) {
	cases := []struct {
		desc      string
		input     int64
		expOutput bool
	}{
		{"test for zero value", 0, true},
		{"test for 60 seconds ago", time.Now().UTC().Unix() - 60, true},
		{"test for plus 60 seconds from now", time.Now().UTC().Unix() + 60, false},
	}
	for _, c := range cases {
		actOuput := isExpired(c.input)
		assert.Equal(t, c.expOutput, actOuput, c.desc)
	}
}

func TestNewToken(t *testing.T) {
	cases := []struct {
		desc      string
		header    *Header
		body      *Body
		secret    *pbauth.Secret
		isExpErr  bool
		expErr    error
		expOutput string
	}{
		{"test for nil header", nil, nil, nil, true, consts.ErrNilHeader, ""},
		{"test for nil body with 256JWT", valid256JWT, nil, nil, true, consts.ErrNilBody, ""},
		{"test for nil body with 512JWT", valid512JWT, nil, nil, true, consts.ErrNilBody, ""},
		{"test for invalid user UUID", valid512JWT, &Body{}, nil, true, consts.ErrInvalidUUID, ""},
		{"test for expired body", valid512JWT, &Body{UUID: "01d3x3wm2nnrdfzp0tka2vw9dx"}, nil, true, consts.ErrExpiredBody, ""},
		{"test for nil secret", valid512JWT, validAdminBody, nil, true, consts.ErrNilSecret, ""},
		{"test for secret zero create timestamp", valid512JWT, validAdminBody,
			&pbauth.Secret{
				Key: "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
			},
			true, consts.ErrInvalidSecretCreateTimestamp, "",
		},
		{"test for secret create timestamp after now", valid512JWT, validAdminBody,
			&pbauth.Secret{
				Key:              "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				CreatedTimestamp: time.Now().UTC().Unix() + 1,
			},
			true, consts.ErrInvalidSecretCreateTimestamp, "",
		},
		{"test for expired secret", valid512JWT, validAdminBody,
			&pbauth.Secret{
				Key:              "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				CreatedTimestamp: validCreatedTimestamp,
			},
			true, consts.ErrExpiredSecret, "",
		},
		{"test for valid admin token", valid512JWT, validAdminBody, validSecret, false, nil, valid512JWTAdminTokenString},
		{"test for invalid 256 Alg with admin", valid256JWT, validAdminBody, validSecret, true, consts.ErrInvalidPermission, ""},
		{"test for JWT support only", valid256NoType, validUserBody, validSecret, true, consts.ErrInvalidJWT, ""},
		{"test for valid user token", valid256JWT, validUserBody, validSecret, false, nil, valid256JWTUserTokenString},
		{"test for expired body", valid256JWT, expiredUserBody, validSecret, true, consts.ErrExpiredBody, ""},
	}
	for _, c := range cases {
		output, err := NewToken(c.header, c.body, c.secret)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error(), c.desc)
		} else {
			assert.Nil(t, err, c.desc)
			assert.Equal(t, c.expOutput, output, c.desc)
		}
	}
}

func TestGetTokenSignature(t *testing.T) {
	cases := []struct {
		desc      string
		header    *Header
		body      *Body
		secret    *pbauth.Secret
		isExpErr  bool
		expErr    error
		expOutput string
	}{
		{"test for nil header", nil, nil, nil, true, consts.ErrNilHeader, ""},
		{"test for nil body with 256JWT", valid256JWT, nil, nil, true, consts.ErrNilBody, ""},
		{"test for nil body with 512JWT", valid512JWT, nil, nil, true, consts.ErrNilBody, ""},
		{"test for invalid user UUID", valid512JWT, &Body{}, nil, true, consts.ErrInvalidUUID, ""},
		{"test for expired body", valid512JWT, &Body{UUID: "01d3x3wm2nnrdfzp0tka2vw9dx"}, nil, true, consts.ErrExpiredBody, ""},
		{"test for nil secret", valid512JWT, validAdminBody, nil, true, consts.ErrNilSecret, ""},
		{"test for secret zero create timestamp", valid512JWT, validAdminBody,
			&pbauth.Secret{
				Key: "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
			},
			true, consts.ErrInvalidSecretCreateTimestamp, "",
		},
		{"test for secret create timestamp after now", valid512JWT, validAdminBody,
			&pbauth.Secret{
				Key:              "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				CreatedTimestamp: time.Now().UTC().Unix() + 1,
			},
			true, consts.ErrInvalidSecretCreateTimestamp, "",
		},
		{"test for expired secret", valid512JWT, validAdminBody,
			&pbauth.Secret{
				Key:              "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				CreatedTimestamp: validCreatedTimestamp,
			},
			true, consts.ErrExpiredSecret, "",
		},
		{"test for valid admin token", valid512JWT, validAdminBody, validSecret, false, nil, valid512JWTAdminTokenString},
		{"test for invalid 256 Alg with admin", valid256JWT, validAdminBody, validSecret, true, consts.ErrInvalidPermission, ""},
		{"test for JWT support only", valid256NoType, validUserBody, validSecret, true, consts.ErrInvalidJWT, ""},
		{"test for valid user token", valid256JWT, validUserBody, validSecret, false, nil, valid256JWTUserTokenString},
		{"test for expired body", valid256JWT, expiredUserBody, validSecret, true, consts.ErrExpiredBody, ""},
	}
	for _, c := range cases {
		output, err := getTokenSignature(c.header, c.body, c.secret)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error(), c.desc)
		} else {
			assert.Nil(t, err, c.desc)
			assert.Equal(t, c.expOutput, output, c.desc)
		}
	}
}

func TestBuildTokenSignature(t *testing.T) {
	cases := []struct {
		desc      string
		header    string
		body      string
		alg       Algorithm
		secret    *pbauth.Secret
		isExpErr  bool
		expErr    error
		expOutput string
	}{
		{"test for empty encoded header", "", "", NoAlg, nil, true, consts.ErrInvalidEncodedHeader, ""},
		{"test for empty encoded body with 256 JWT", encoded256JWTHeader, "", NoAlg, nil, true, consts.ErrInvalidEncodedBody, ""},
		{"test for empty encoded body with 512 JWT", encoded512JWTHeader, "", NoAlg, nil, true, consts.ErrInvalidEncodedBody, ""},
		{"test for nil secret", encoded256JWTHeader, encodedAdminBody, NoAlg, nil, true, consts.ErrNilSecret, ""},
		{"test with valid admin header + body", encoded512JWTHeader, encodedAdminBody, Hs512, validSecret, false, nil, valid512JWTAdminTokenString},
		{"test with valid user header + body", encoded256JWTHeader, encodedUserBody, Hs256, validSecret, false, nil, valid256JWTUserTokenString},
	}
	for _, c := range cases {
		actOutput, err := buildTokenSignature(c.header, c.body, c.alg, c.secret)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error(), c.desc)
		} else {
			assert.Equal(t, c.expOutput, actOutput, c.desc)
		}
	}
}

func TestBase64Encode(t *testing.T) {
	cases := []struct {
		desc      string
		input     interface{}
		isExpErr  bool
		expErr    error
		expOutput string
	}{
		{"test for nil input", nil, true, consts.ErrNilInterface, ""},
		{"test for valid 256 JWT", valid256JWT, false, nil, encoded256JWTHeader},
		{"test for valid 512 JWT", valid512JWT, false, nil, encoded512JWTHeader},
		{"test for valid admin body", validAdminBody, false, nil, encodedAdminBody},
		{"test for valid user body", validUserBody, false, nil, encodedUserBody},
	}
	for _, c := range cases {
		output, err := base64Encode(c.input)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error(), c.desc)
		} else {
			assert.Nil(t, err, c.desc)
			assert.Equal(t, c.expOutput, output, c.desc)
		}
	}
}

func TestBase64Decode(t *testing.T) {
	cases := []struct {
		desc       string
		input      string
		isExpErr   bool
		expErr     error
		expOutput  interface{}
		structType int
	}{
		{"test for empty string", "", true, consts.ErrEmptyString, nil, 0},
		{"test for valid 256 JWT", encoded256JWTHeader, false, nil, valid256JWT, 0},
		{"test for valid 512 JWT", encoded512JWTHeader, false, nil, valid512JWT, 0},
		{"test for valid admin body", encodedAdminBody, false, nil, validAdminBody, 1},
		{"test for valid user body", encodedUserBody, false, nil, validUserBody, 1},
	}
	for _, c := range cases {
		output, err := base64Decode(c.input)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error(), c.desc)
		} else {
			assert.Nil(t, err, c.desc)
			switch c.structType {
			case structHeader:
				var o *Header
				err := json.Unmarshal([]byte(output), &o)
				assert.Nil(t, err, c.desc)
				assert.Equal(t, o, c.expOutput, c.desc)
			case structBody:
				var o *Body
				err := json.Unmarshal([]byte(output), &o)
				assert.Nil(t, err, c.desc)
				assert.Equal(t, o, c.expOutput, c.desc)
			}
		}
	}
}

func TestHashSignature(t *testing.T) {
	cases := []struct {
		desc           string
		alg            Algorithm
		signatureValue string
		secret         *pbauth.Secret
		isExpErr       bool
		expErr         error
		expOutput      string
	}{
		{"test for empty signatureValue", NoAlg, "", nil, true, consts.ErrInvalidSignatureValue, ""},
		{"test for nil secret", Hs512, valid512JWTAdminSignature, nil, true, consts.ErrNilSecret, ""},
		{"test for valid admin signature", Hs512, valid512JWTAdminSignature, validSecret, false, nil, valid512JWTAdminHAS},
		{"test for valid user signature", Hs256, valid256JWTUserSignature, validSecret, false, nil, valid256JWTUserHAS},
		{"test for no hash algorithm", NoAlg, valid256JWTUserSignature, validSecret, true, consts.ErrNoHashAlgorithm, ""},
	}
	for _, c := range cases {
		actOuput, err := hashSignature(c.alg, c.signatureValue, c.secret)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error(), c.desc)
		} else {
			assert.Nil(t, err, c.desc)
			assert.Equal(t, c.expOutput, actOuput, c.desc)
		}
	}
}

func TestIsEquivalentHash(t *testing.T) {
	cases := []struct {
		desc           string
		alg            Algorithm
		signatureValue string
		secret         *pbauth.Secret
		hashedValue    string
		expOutput      bool
	}{
		{"test for nil secret", Hs512, valid512JWTAdminSignature, nil, "", false},
		{"test valid 512 admin signature", Hs512, valid512JWTAdminSignature, validSecret, valid512JWTAdminHAS, true},
		{"test valid 256 user signature", Hs256, valid256JWTUserSignature, validSecret, valid256JWTUserHAS, true},
	}
	for _, c := range cases {
		actOuput := isEquivalentHash(c.alg, c.signatureValue, c.secret, c.hashedValue)
		assert.Equal(t, c.expOutput, actOuput, c.desc)
	}
}

func TestExtractUUID(t *testing.T) {
	cases := []struct {
		desc        string
		tokenString string
		expOutput   string
	}{
		{"test for empty token string", "", ""},
		{"test for invalid token string", "asdadqweqw131231", ""},
		{"test valid token string", valid256JWTUserTokenString, "22d3x3wm2nnrdfzp0tka2vw9dx"},
	}
	for _, c := range cases {
		actOuput := extractUUID(c.tokenString)
		assert.Equal(t, c.expOutput, actOuput, c.desc)
	}
}
