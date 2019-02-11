package consts

import "errors"

var (
	ErrNilToken  = errors.New("nil token")
	ErrNilSecret = errors.New("nil secret")
)
