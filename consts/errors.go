package consts

import "errors"

var (
	ErrNilIdentification = errors.New("nil identification")
	ErrNilBody           = errors.New("nil body")
	ErrNilSecret         = errors.New("nil secret")
	ErrEmptyToken        = errors.New("empty token string")
	ErrExpiredToken      = errors.New("expired token string")
	ErrIncompleteToken   = errors.New("token should contain header, body, signature")
	ErrInvalidSignature  = errors.New("invalid signature")
	ErrInvalidPermission = errors.New("unauthorized permission")
)
