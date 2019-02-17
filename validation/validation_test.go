package validation

import (
	"github.com/hwsc-org/hwsc-lib/consts"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestValidateUserUUID(t *testing.T) {
	cases := []struct {
		uuid     string
		isExpErr bool
	}{
		{"01d3x3wm2nnrdfzp0tka2vw9dx", false},
		{"", true},
		{"01d1na5ekzr7p98hragv5fmvx", true},
		{"abcd", true},
	}

	for _, c := range cases {
		err := ValidateUserUUID(c.uuid)

		if c.isExpErr {
			assert.EqualError(t, err, consts.ErrInvalidUUID.Error())
		} else {
			assert.Nil(t, err)
		}
	}
}
