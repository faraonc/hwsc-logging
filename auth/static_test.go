package auth

import (
	"encoding/json"
	pbauth "github.com/hwsc-org/hwsc-api-blocks/lib"
	"github.com/hwsc-org/hwsc-lib/consts"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

const (
	structHeader = iota
	structBody
)

var (
	validCreatedTimestamp    = time.Now().UTC().Unix() - 60 // seconds
	validExpirationTimestamp = time.Unix(validCreatedTimestamp, 0).AddDate(0, 0, 7).UTC().Unix()
	// validHeader and encodedHeader are dependent to each other
	validHeader = &Header{
		Alg:      Hs512,
		TokenTyp: Jwt,
	}
	encodedHeader = "eyJBbGciOjIsIlRva2VuVHlwIjoxfQ"
	// validBody and encodedBody are dependent to each other
	validBody = &Body{
		UUID:                "01d3x3wm2nnrdfzp0tka2vw9dx",
		Permission:          Admin,
		ExpirationTimestamp: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).Unix(),
	}
	encodedBody = "eyJVVUlEIjoiMDFkM3gzd20ybm5yZGZ6cDB0a2Eydnc5ZHgiLCJQZXJtaXNzaW9uIjozLCJFeHBpcmF0aW9uVGltZXN0YW1wIjoxNTc3ODM2ODAwfQ"
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
				Token: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1dWlkIjoiMTIzNDU2Nzg5MCIsInBlcm1pc3Npb24iOiJUb2tlbi5BRE1JTiIsImV4cGlyYXRpb25fdGltZSI6MTU0OTA5MzkxMH0.OZFQ_zU1F2BJm6kyYzsBns5qmOxbVbUnQV2SU1B_kyPfXPOmUd0fddRvF0I3IqaDz-55H7Q80w8zQyldMQ7AAg",
				Secret: &pbauth.Secret{
					Key:                 "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
					CreatedTimestamp:    validCreatedTimestamp,
					ExpirationTimestamp: validExpirationTimestamp,
				},
			}, false, nil,
		},
	}

	for _, c := range cases {
		err := validateIdentification(c.input)
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
		{validHeader, false, nil},
	}
	for _, c := range cases {
		err := validateHeader(c.input)
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
		{&Body{UUID: "01d3x3wm2nnrdfzp0tka2vw9dx"}, false, nil},
	}
	for _, c := range cases {
		err := validateBody(c.input)
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
				CreatedTimestamp: time.Now().UTC().Unix() + 1,
			}, true, consts.ErrInvalidSecretCreateTimestamp,
		},
		{
			&pbauth.Secret{
				Key:                 "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				CreatedTimestamp:    validCreatedTimestamp,
				ExpirationTimestamp: validExpirationTimestamp,
			}, false, nil,
		},
	}
	for _, c := range cases {
		err := validateSecret(c.input)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error())
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestNewToken(t *testing.T) {
	cases := []struct {
		header   *Header
		body     *Body
		secret   *pbauth.Secret
		isExpErr bool
		expErr   error
	}{
		{nil, nil, nil, true, consts.ErrNilHeader},
		{validHeader, nil, nil, true, consts.ErrNilBody},
		{validHeader, &Body{}, nil, true, consts.ErrInvalidUUID},
		{
			validHeader,
			&Body{UUID: "01d3x3wm2nnrdfzp0tka2vw9dx"},
			nil, true, consts.ErrNilSecret,
		},
		{
			validHeader,
			&Body{UUID: "01d3x3wm2nnrdfzp0tka2vw9dx"},
			&pbauth.Secret{
				Key: "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
			},
			true, consts.ErrInvalidSecretCreateTimestamp,
		},
		{
			validHeader,
			&Body{UUID: "01d3x3wm2nnrdfzp0tka2vw9dx"},
			&pbauth.Secret{
				Key:              "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				CreatedTimestamp: time.Now().UTC().Unix() + 1,
			},
			true, consts.ErrInvalidSecretCreateTimestamp,
		},
		{
			validHeader,
			&Body{UUID: "01d3x3wm2nnrdfzp0tka2vw9dx"},
			&pbauth.Secret{
				Key:              "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				CreatedTimestamp: validCreatedTimestamp,
			},
			true, consts.ErrExpiredSecret,
		},
		{
			validHeader,
			&Body{UUID: "01d3x3wm2nnrdfzp0tka2vw9dx"},
			&pbauth.Secret{
				Key:                 "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				CreatedTimestamp:    validCreatedTimestamp,
				ExpirationTimestamp: validExpirationTimestamp,
			},
			false, nil,
		},
	}
	for _, c := range cases {
		output, err := NewToken(c.header, c.body, c.secret)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error())
		} else {
			assert.Nil(t, err)
			assert.NotEqual(t, "", output)
		}
	}
}

func TestGetTokenSignature(t *testing.T) {
	cases := []struct {
		header   *Header
		body     *Body
		secret   *pbauth.Secret
		isExpErr bool
		expErr   error
	}{
		{nil, nil, nil, true, consts.ErrNilHeader},
		{validHeader, nil, nil, true, consts.ErrNilBody},
		{validHeader, &Body{}, nil, true, consts.ErrInvalidUUID},
		{
			validHeader,
			&Body{UUID: "01d3x3wm2nnrdfzp0tka2vw9dx"},
			nil, true, consts.ErrNilSecret,
		},
		{
			validHeader,
			&Body{UUID: "01d3x3wm2nnrdfzp0tka2vw9dx"},
			&pbauth.Secret{
				Key: "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
			},
			true, consts.ErrInvalidSecretCreateTimestamp,
		},
		{
			validHeader,
			&Body{UUID: "01d3x3wm2nnrdfzp0tka2vw9dx"},
			&pbauth.Secret{
				Key:              "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				CreatedTimestamp: time.Now().UTC().Unix() + 1,
			},
			true, consts.ErrInvalidSecretCreateTimestamp,
		},
		{
			validHeader,
			&Body{UUID: "01d3x3wm2nnrdfzp0tka2vw9dx"},
			&pbauth.Secret{
				Key:              "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				CreatedTimestamp: validCreatedTimestamp,
			},
			true, consts.ErrExpiredSecret,
		},
		{
			validHeader,
			&Body{UUID: "01d3x3wm2nnrdfzp0tka2vw9dx"},
			&pbauth.Secret{
				Key:                 "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				CreatedTimestamp:    validCreatedTimestamp,
				ExpirationTimestamp: validExpirationTimestamp,
			},
			false, nil,
		},
	}
	for _, c := range cases {
		output, err := getTokenSignature(c.header, c.body, c.secret)
		if c.isExpErr {
			assert.EqualError(t, err, c.expErr.Error())
		} else {
			assert.Nil(t, err)
			assert.NotEqual(t, "", output)
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
		{validHeader, false, nil, encodedHeader},
		{validBody, false, nil, encodedBody},
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
		{encodedHeader, false, nil, validHeader, 0},
		{encodedBody, false, nil, validBody, 1},
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
