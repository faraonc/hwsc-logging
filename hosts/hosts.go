package hosts

import "fmt"

// Host contains server configuration
// `json:"address"` are key:value tags that can add meta information to structs
// there can be json tags, yaml tags, xml, bson, protobuf, etc.
// When json.Unmarshaling JSON file,
// takes the "address" JSON property, and put it in the Address field of Host
type Host struct {
	Address string `json:"address"`
	Port    string `json:"port"`
	Network string `json:"network"`
}

// UserDBHost contains User database configurations
type UserDBHost struct {
	Host     string `json:"host"`
	Name     string `json:"db"`
	User     string `json:"user"`
	Password string `json:"password"`
	Port     string `json:"port"`
	SSLMode  string `json:"sslmode"`
}

// SMTPHost contains SMTP email configurations
type SMTPHost struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// String prints readable address and port using
func (h *Host) String() string {
	return fmt.Sprintf("%s:%s", h.Address, h.Port)
}
