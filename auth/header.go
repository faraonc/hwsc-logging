package auth

// Algorithm is the type of hashing algorithm to use.
type Algorithm int32

const (
	// NoALg default zero value
	NoALg Algorithm = iota
	// Hs256 use SHA256
	Hs256
	// Hs512 use SHA512 for admin level permission
	Hs512
)

// TokenType used for authorization.
type TokenType int32

const (
	// NoTpe default zero value
	NoTpe TokenType = iota
	// Jwt JSON Web Token
	Jwt
)

// Header contains the algorithm and token type used to sign the token.
type Header struct {
	Alg      Algorithm
	TokenTyp TokenType
}
