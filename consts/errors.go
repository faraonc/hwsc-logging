package consts

import "errors"

var (
	ErrNilInterface                 = errors.New("nil interface")
	ErrEmptyString                  = errors.New("empty string")
	ErrNilIdentification            = errors.New("nil identification")
	ErrNilHeader                    = errors.New("nil header")
	ErrNilBody                      = errors.New("nil body")
	ErrNilSecret                    = errors.New("nil secret")
	ErrExpiredBody                  = errors.New("expired body")
	ErrEmptyToken                   = errors.New("empty token string")
	ErrEmptySecret                  = errors.New("empty secret key")
	ErrExpiredSecret                = errors.New("expired secret key")
	ErrInvalidSecretCreateTimestamp = errors.New("invalid secret create timestamp")
	ErrExpiredToken                 = errors.New("expired token string")
	ErrIncompleteToken              = errors.New("token should contain header, body, signature")
	ErrInvalidSignature             = errors.New("invalid signature")
	ErrInvalidPermission            = errors.New("unauthorized permission")
	ErrInvalidUUID                  = errors.New("invalid uuid")
	ErrInvalidEncodedHeader         = errors.New("invalid encoded header")
	ErrInvalidEncodedBody           = errors.New("invalid encoded body")
	ErrInvalidSignatureValue        = errors.New("invalid signature value")
	ErrNoHashAlgorithm              = errors.New("no hashing algorithm")
)
