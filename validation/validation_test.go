package validation

import (
	"github.com/hwsc-org/hwsc-lib/consts"
	"github.com/oklog/ulid"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"strings"
	"testing"
	"time"
)

func TestValidateUUID(t *testing.T) {
	// generate a valid uuid
	currTime := time.Now().UTC()
	entropy := rand.New(rand.NewSource(currTime.UnixNano()))

	uuid, err := ulid.New(ulid.Timestamp(currTime), entropy)
	assert.Nil(t, err)
	assert.NotNil(t, uuid)

	cases := []struct {
		uuid     string
		isExpErr bool
	}{
		{strings.ToLower(uuid.String()), false},
		{"", true},
		{"01d1na5ekzr7p98hragv5fmvx", true},
		{"abcd", true},
	}

	for _, c := range cases {
		err := validateUUID(c.uuid)

		if c.isExpErr {
			assert.EqualError(t, err, consts.ErrInvalidUUID.Error())
		} else {
			assert.Nil(t, err)
		}
	}
}