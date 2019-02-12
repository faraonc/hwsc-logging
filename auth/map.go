package auth

var (
	// PermissionStringMap maps Permission enum(int) values to its string values
	PermissionStringMap = map[Permission]string{
		NoPermission:     "NO_PERM",
		UserRegistration: "USER_REGISTRATION",
		User:             "USER",
		Admin:            "ADMIN",
	}

	// PermissionEnumMap maps string permission values to its enum(int) values
	PermissionEnumMap = map[string]Permission{
		PermissionStringMap[NoPermission]:     NoPermission,
		PermissionStringMap[UserRegistration]: UserRegistration,
		PermissionStringMap[User]:             User,
		PermissionStringMap[Admin]:            Admin,
	}
)
