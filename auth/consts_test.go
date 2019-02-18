package auth

import (
	pbauth "github.com/hwsc-org/hwsc-api-blocks/lib"
	"time"
)

const (
	structHeader = iota
	structBody
)

var (
	validCreatedTimestamp    = time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	validExpirationTimestamp = time.Unix(validCreatedTimestamp, 0).AddDate(30, 0, 0).UTC().Unix()
	validSecretKey           = "j2Yzh-VcIm-lYUzBuqt8TVPeUHNYB5MP1gWvz3Bolow="
	// valid256JWT and encoded256JWTHeader are dependent to each other
	valid256JWT = &Header{
		Alg:      Hs256,
		TokenTyp: Jwt,
	}
	encoded256JWTHeader = "eyJBbGciOjEsIlRva2VuVHlwIjoxfQ"
	// valid512JWT and encoded512JWTHeader are dependent to each other
	valid512JWT = &Header{
		Alg:      Hs512,
		TokenTyp: Jwt,
	}
	encoded512JWTHeader = "eyJBbGciOjIsIlRva2VuVHlwIjoxfQ"
	// validAdminBody and encodedAdminBody are dependent to each other
	validAdminBody = &Body{
		UUID:                "01d3x3wm2nnrdfzp0tka2vw9dx",
		Permission:          Admin,
		ExpirationTimestamp: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).Unix(),
	}
	encodedAdminBody = "eyJVVUlEIjoiMDFkM3gzd20ybm5yZGZ6cDB0a2Eydnc5ZHgiLCJQZXJtaXNzaW9uIjozLCJFeHBpcmF0aW9uVGltZXN0YW1wIjoxODkzNDU2MDAwfQ"
	// validUserBody and encodedUserBody are dependent to each other
	validUserBody = &Body{
		UUID:                "22d3x3wm2nnrdfzp0tka2vw9dx",
		Permission:          User,
		ExpirationTimestamp: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).Unix(),
	}
	encodedUserBody = "eyJVVUlEIjoiMjJkM3gzd20ybm5yZGZ6cDB0a2Eydnc5ZHgiLCJQZXJtaXNzaW9uIjoyLCJFeHBpcmF0aW9uVGltZXN0YW1wIjoxODkzNDU2MDAwfQ"
	validSecret     = &pbauth.Secret{
		Key:                 validSecretKey,
		CreatedTimestamp:    validCreatedTimestamp,
		ExpirationTimestamp: validExpirationTimestamp,
	}
	valid512JWTAdminTokenString = "eyJBbGciOjIsIlRva2VuVHlwIjoxfQ.eyJVVUlEIjoiMDFkM3gzd20ybm5yZGZ6cDB0a2Eydnc5ZHgiLCJQZXJtaXNzaW9uIjozLCJFeHBpcmF0aW9uVGltZXN0YW1wIjoxODkzNDU2MDAwfQ.8lVhZo_W6KmGI2oi5JNHioDvPq2Yl86v4uae3RfKc-qoKUwHNxFtXO2NFmChsi35__t1uC_SD-Ay_MoateeDNg=="
	valid512JWTAdminSignature   = "eyJBbGciOjIsIlRva2VuVHlwIjoxfQ.eyJVVUlEIjoiMDFkM3gzd20ybm5yZGZ6cDB0a2Eydnc5ZHgiLCJQZXJtaXNzaW9uIjozLCJFeHBpcmF0aW9uVGltZXN0YW1wIjoxODkzNDU2MDAwfQ"
	valid512JWTAdminHAS         = "8lVhZo_W6KmGI2oi5JNHioDvPq2Yl86v4uae3RfKc-qoKUwHNxFtXO2NFmChsi35__t1uC_SD-Ay_MoateeDNg=="
	valid256JWTUserTokenString  = "eyJBbGciOjEsIlRva2VuVHlwIjoxfQ.eyJVVUlEIjoiMjJkM3gzd20ybm5yZGZ6cDB0a2Eydnc5ZHgiLCJQZXJtaXNzaW9uIjoyLCJFeHBpcmF0aW9uVGltZXN0YW1wIjoxODkzNDU2MDAwfQ.e5-zlHh02bJeZ7rVGuSVVTUG1k1L_aKKRddXXojpcxI="
	valid256JWTUserSignature    = "eyJBbGciOjEsIlRva2VuVHlwIjoxfQ.eyJVVUlEIjoiMjJkM3gzd20ybm5yZGZ6cDB0a2Eydnc5ZHgiLCJQZXJtaXNzaW9uIjoyLCJFeHBpcmF0aW9uVGltZXN0YW1wIjoxODkzNDU2MDAwfQ"
	valid256JWTUserHAS          = "e5-zlHh02bJeZ7rVGuSVVTUG1k1L_aKKRddXXojpcxI="

	// invalid because HS256 with Admin permission
	invalid256JWTTokenString = "eyJBbGciOjEsIlRva2VuVHlwIjoxfQ.eyJVVUlEIjoiMDFkM3gzd20ybm5yZGZ6cDB0a2Eydnc5ZHgiLCJQZXJtaXNzaW9uIjozLCJFeHBpcmF0aW9uVGltZXN0YW1wIjoxODkzNDU2MDAwfQ.xtOMEMbgD9YH0SDVChgSy6vykf9z-9eD0_pCK--uwQQ="
	valid256NoType           = &Header{
		Alg:      Hs256,
		TokenTyp: NoType,
	}
	invalid256NoTypeTokenString = "eyJBbGciOjEsIlRva2VuVHlwIjowfQ.eyJVVUlEIjoiMjJkM3gzd20ybm5yZGZ6cDB0a2Eydnc5ZHgiLCJQZXJtaXNzaW9uIjoyLCJFeHBpcmF0aW9uVGltZXN0YW1wIjoxODkzNDU2MDAwfQ.X04m8Fz9oR5Gd9vaUbp2Cj6orzyyHf77PpmzEQK5cKw="
	expiredUserBody             = &Body{
		UUID:                "3d3x3wm2nnrdfzp0tka2svw9dx",
		Permission:          User,
		ExpirationTimestamp: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC).Unix(),
	}
	invalidUUIDUserToken = "eyJBbGciOjEsIlRva2VuVHlwIjoxfQ.eyJVVUlEIjoiM2QzeDN3bTJubnJkZnpwMHRrYTJ2dzlkeCIsIlBlcm1pc3Npb24iOjIsIkV4cGlyYXRpb25UaW1lc3RhbXAiOjE0ODMyMjg4MDB9.R_kt6M92zt8FlSJF5LZcSLbPgH0l3ZzujDAq6kpAtC8="
	expiredUserToken     = "eyJBbGciOjEsIlRva2VuVHlwIjoxfQ.eyJVVUlEIjoiM2QzeDN3bTJubnJkZnpwMHRrYTJzdnc5ZHgiLCJQZXJtaXNzaW9uIjoyLCJFeHBpcmF0aW9uVGltZXN0YW1wIjoxNDgzMjI4ODAwfQ.XpNCF264jqlW6VnXq4yJPERPY--c3TNkG8fSlu8okPs="
	/*
		diffUserBody = &Body{
			UUID:                "11d3x3wm2nnrdfzp0tka2vw9dx",
			Permission:          User,
			ExpirationTimestamp: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).Unix(),
		}
	*/
	// Use different user
	fakeToken = "eyJBbGciOjEsIlRva2VuVHlwIjoxfQ.eyJVVUlEIjoiMTFkM3gzd20ybm5yZGZ6cDB0a2Eydnc5ZHgiLCJQZXJtaXNzaW9uIjoyLCJFeHBpcmF0aW9uVGltZXN0YW1wIjoxODkzNDU2MDAwfQ.e5-zlHh02bJeZ7rVGuSVVTUG1k1L_aKKRddXXojpcxI="
)
