package auth

// Permission required to use the service
type Permission int32

const (
	// NoPermission user is not allowed to use the service
	NoPermission Permission = iota
	// User is only allowed to use services based on the ownership
	User
	// Admin is allowed to perform CRUD on everything
	Admin
)

// Body contains the user's uuid, permission level, and expiration timestamp.
type Body struct {
	UUID                string
	Permission          Permission
	ExpirationTimestamp int64
}
