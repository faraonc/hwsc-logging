package auth

const (
	strNoPerm           = "NO_PERM"
	strUserRegistration = "USER_REGISTRATION"
	strUser             = "USER"
	strAdmin            = "ADMIN"
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
)
