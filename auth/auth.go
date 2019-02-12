package auth

import (
	"fmt"
	pb "github.com/hwsc-org/hwsc-api-blocks/int/hwsc-app-gateway-svc/proto"
)

// Authorize the given Token using a Secret
// func Authorize(token *pb.Token) {
// 	fmt.Println("Authorize")
// }

// Invalidate the Token
func Invalidate() {
	fmt.Println("Invalidate")
}

// HasExpired checks if the Token has expired
func HasExpired() bool {
	fmt.Println("HasExpired")
	return false
}

// IsAuthorized checks if the Token is authorized using a Secret
func IsAuthorized() bool {
	fmt.Println("IsAuthorized")
	return true
}
