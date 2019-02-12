package auth

var (
	PermissionStringMap map[Permission]string
	PermissionEnumMap map[string]Permission
)

func init() {
	PermissionStringMap = map[Permission]string {
		NoPermission: "NO_PERM",
		UserRegistration: "USER_REGISTRATION",
		User: "USER",
		Admin: "ADMIN",
	}

	PermissionEnumMap = map[string]Permission {
		PermissionStringMap[NoPermission]: NoPermission,
		PermissionStringMap[UserRegistration]: UserRegistration,
		PermissionStringMap[User]: User,
		PermissionStringMap[Admin]: Admin,
	}
}