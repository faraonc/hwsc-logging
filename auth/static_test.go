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
	validCreatedTimestamp    = time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	validExpirationTimestamp = time.Unix(validCreatedTimestamp, 0).AddDate(30, 0, 0).UTC().Unix()
	// valid256 and encoded256Header are dependent to each other
	valid256 = &Header{
		Alg:      Hs256,
		TokenTyp: Jwt,
	}
	encoded256Header = "eyJBbGciOjEsIlRva2VuVHlwIjoxfQ"
	// valid512 and encoded512Header are dependent to each other
	valid512 = &Header{
		Alg:      Hs512,
		TokenTyp: Jwt,
	}
	encoded512Header = "eyJBbGciOjIsIlRva2VuVHlwIjoxfQ"
	// validBody and encodedBody are dependent to each other
	validBody = &Body{
		UUID:                "01d3x3wm2nnrdfzp0tka2vw9dx",
		Permission:          Admin,
		ExpirationTimestamp: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).Unix(),
	}
	encodedBody = "eyJVVUlEIjoiMDFkM3gzd20ybm5yZGZ6cDB0a2Eydnc5ZHgiLCJQZXJtaXNzaW9uIjozLCJFeHBpcmF0aW9uVGltZXN0YW1wIjoxODkzNDU2MDAwfQ"
	validSecret = &pbauth.Secret{
		Key:                 "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
		CreatedTimestamp:    validCreatedTimestamp,
		ExpirationTimestamp: validExpirationTimestamp,
	}
	valid256TokenString = "eyJBbGciOjEsIlRva2VuVHlwIjoxfQ.eyJVVUlEIjoiMDFkM3gzd20ybm5yZGZ6cDB0a2Eydnc5ZHgiLCJQZXJtaXNzaW9uIjozLCJFeHBpcmF0aW9uVGltZXN0YW1wIjoxODkzNDU2MDAwfQ.xtOMEMbgD9YH0SDVChgSy6vykf9z-9eD0_pCK--uwQQ="
	valid256Signature   = "eyJBbGciOjEsIlRva2VuVHlwIjoxfQ.eyJVVUlEIjoiMDFkM3gzd20ybm5yZGZ6cDB0a2Eydnc5ZHgiLCJQZXJtaXNzaW9uIjozLCJFeHBpcmF0aW9uVGltZXN0YW1wIjoxODkzNDU2MDAwfQ"
	valid256HAS         = "xtOMEMbgD9YH0SDVChgSy6vykf9z-9eD0_pCK--uwQQ="
	valid512TokenString = "eyJBbGciOjIsIlRva2VuVHlwIjoxfQ.eyJVVUlEIjoiMDFkM3gzd20ybm5yZGZ6cDB0a2Eydnc5ZHgiLCJQZXJtaXNzaW9uIjozLCJFeHBpcmF0aW9uVGltZXN0YW1wIjoxODkzNDU2MDAwfQ.8lVhZo_W6KmGI2oi5JNHioDvPq2Yl86v4uae3RfKc-qoKUwHNxFtXO2NFmChsi35__t1uC_SD-Ay_MoateeDNg=="
	valid512Signature   = "eyJBbGciOjIsIlRva2VuVHlwIjoxfQ.eyJVVUlEIjoiMDFkM3gzd20ybm5yZGZ6cDB0a2Eydnc5ZHgiLCJQZXJtaXNzaW9uIjozLCJFeHBpcmF0aW9uVGltZXN0YW1wIjoxODkzNDU2MDAwfQ"
	valid512HAS         = "8lVhZo_W6KmGI2oi5JNHioDvPq2Yl86v4uae3RfKc-qoKUwHNxFtXO2NFmChsi35__t1uC_SD-Ay_MoateeDNg=="
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
		{valid256, false, nil},
		{valid512, false, nil},
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
		{&Body{UUID: "01d3x3wm2nnrdfzp0tka2vw9dx"}, true, consts.ErrExpiredBody},
		{validBody, false, nil},
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
		{valid256, nil, nil, true, consts.ErrNilBody, ""},
		{valid512, nil, nil, true, consts.ErrNilBody, ""},
		{valid512, &Body{}, nil, true, consts.ErrInvalidUUID, ""},
		{valid512, &Body{UUID: "01d3x3wm2nnrdfzp0tka2vw9dx"}, nil, true, consts.ErrExpiredBody, ""},
		{valid512, validBody, nil, true, consts.ErrNilSecret, ""},
		{valid512, validBody,
			&pbauth.Secret{
				Key: "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
			},
			true, consts.ErrInvalidSecretCreateTimestamp, "",
		},
		{valid512, validBody,
			&pbauth.Secret{
				Key:              "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				CreatedTimestamp: time.Now().UTC().Unix() + 1,
			},
			true, consts.ErrInvalidSecretCreateTimestamp, "",
		},
		{valid512, validBody,
			&pbauth.Secret{
				Key:              "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				CreatedTimestamp: validCreatedTimestamp,
			},
			true, consts.ErrExpiredSecret, "",
		},
		{valid512, validBody, validSecret, false, nil, valid512TokenString},
		{valid256, validBody, validSecret, false, nil, valid256TokenString},
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
		{valid256, nil, nil, true, consts.ErrNilBody, ""},
		{valid512, nil, nil, true, consts.ErrNilBody, ""},
		{valid512, &Body{}, nil, true, consts.ErrInvalidUUID, ""},
		{
			valid512,
			&Body{UUID: "01d3x3wm2nnrdfzp0tka2vw9dx"},
			nil, true, consts.ErrExpiredBody, "",
		},
		{valid512, validBody, nil, true, consts.ErrNilSecret, ""},
		{valid512, validBody,
			&pbauth.Secret{
				Key: "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
			},
			true, consts.ErrInvalidSecretCreateTimestamp, ",",
		},
		{valid512, validBody,
			&pbauth.Secret{
				Key:              "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				CreatedTimestamp: time.Now().UTC().Unix() + 1,
			},
			true, consts.ErrInvalidSecretCreateTimestamp, "",
		},
		{valid512, validBody,
			&pbauth.Secret{
				Key:              "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow=",
				CreatedTimestamp: validCreatedTimestamp,
			},
			true, consts.ErrExpiredSecret, "",
		},
		{valid512, validBody, validSecret, false, nil, valid512TokenString},
		{valid256, validBody, validSecret, false, nil, valid256TokenString},
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
		{encoded256Header, "", NoAlg, nil, true, consts.ErrInvalidEncodedBody, ""},
		{encoded512Header, "", NoAlg, nil, true, consts.ErrInvalidEncodedBody, ""},
		{encoded256Header, encodedBody, NoAlg, nil, true, consts.ErrNilSecret, ""},
		{encoded256Header, encodedBody, Hs256, validSecret, false, consts.ErrNilSecret, valid256TokenString},
		{encoded512Header, encodedBody, Hs512, validSecret, false, consts.ErrNilSecret, valid512TokenString},
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
		{valid256, false, nil, encoded256Header},
		{valid512, false, nil, encoded512Header},
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
		{encoded256Header, false, nil, valid256, 0},
		{encoded512Header, false, nil, valid512, 0},
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
		{Hs256, valid256Signature, nil, true, consts.ErrNilSecret, ""},
		{Hs512, valid512Signature, nil, true, consts.ErrNilSecret, ""},
		{NoAlg, valid256Signature, validSecret, true, consts.ErrNoHashAlgorithm, valid256HAS},
		{Hs256, valid256Signature, validSecret, false, nil, valid256HAS},
		{Hs512, valid512Signature, validSecret, false, nil, valid512HAS},
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
		{Hs256, valid256Signature, nil, "", false},
		{Hs512, valid512Signature, nil, "", false},
		{Hs256, valid256Signature, validSecret, valid512HAS, false},
		{Hs512, valid512Signature, validSecret, valid256HAS, false},
		{Hs256, valid256Signature, validSecret, valid256HAS, true},
		{Hs512, valid512Signature, validSecret, valid512HAS, true},
	}
	for _, c := range cases {
		actOuput := isEquivalentHash(c.alg, c.signatureValue, c.secret, c.hashedValue)
		assert.Equal(t, c.expOutput, actOuput)
	}
}
