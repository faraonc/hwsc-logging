package auth

const (
	strNoPerm           = "NO_PERM"
	strUserRegistration = "USER_REGISTRATION"
	strUser             = "USER"
	strAdmin            = "ADMIN"
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

	// SignatureBytesMap maps algorithm to number of bytes needed for token size
	SignatureBytesMap = map[Algorithm]int{
		Hs256: 32,
		Hs512: 64,
	}
)
