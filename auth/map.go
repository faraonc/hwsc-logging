package auth

const (
	strNoPerm           = "NO_PERM"
	strUserRegistration = "USER_REGISTRATION"
	strUser             = "USER"
	strAdmin            = "ADMIN"
	strJWT              = "JWT"
	strNoType           = "NO_TYPE"
	strNoAlg            = "NO_ALG"
	strHs256            = "HS256"
	strHs512            = "HS512"
	// SecretByteSize bytes used to generate secret key
	SecretByteSize = 32
)

var (
	// PermissionStringMap maps Permission enum(int) values to its string values
	PermissionStringMap = map[Permission]string{
		NoPermission:     strNoPerm,
		UserRegistration: strUserRegistration,
		User:             strUser,
		Admin:            strAdmin,
	}

	// PermissionEnumMap maps string permission values to its enum(int) values
	PermissionEnumMap = map[string]Permission{
		strNoPerm:           NoPermission,
		strUserRegistration: UserRegistration,
		strUser:             User,
		strAdmin:            Admin,
	}

	// AlgorithmMap maps permission level to algorithm type
	AlgorithmMap = map[Permission]Algorithm{
		NoPermission:     Hs256,
		UserRegistration: Hs256,
		User:             Hs256,
		Admin:            Hs512,
	}

	// TokenTypeStringMap maps enum TokenType to its string value
	TokenTypeStringMap = map[TokenType]string{
		NoType: strNoType,
		Jwt:    strJWT,
	}

	// AlgorithmStringMap maps enum Algorithm to its string value
	AlgorithmStringMap = map[Algorithm]string{
		NoAlg: strNoAlg,
		Hs256: strHs256,
		Hs512: strHs512,
	}
)
