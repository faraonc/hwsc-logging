package validation

import (
	"github.com/hwsc-org/hwsc-lib/consts"
	"github.com/oklog/ulid"
	"strings"
)

// validateUUID ensures uuid is not a zero value and matches format set by ulid package
// Returns error if zero value or invalid uuid (determined by ulid package)
func validateUUID(uuid string) error {
	if uuid == "" {
		return consts.ErrInvalidUUID
	}

	id, err := ulid.ParseStrict(strings.ToUpper(uuid))
	if err != nil {
		if err.Error() == "ulid: bad data size when unmarshaling" {
			return consts.ErrInvalidUUID
		}
		return err
	}

	if strings.ToLower(id.String()) != uuid {
		return consts.ErrInvalidUUID
	}

	return nil
}