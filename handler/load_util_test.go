package handler

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestUnitDurationParse(t *testing.T) {
	d, err := time.ParseDuration("1m0s")
	assert.Nil(t, err)
	assert.Equal(t, time.Minute, d)
}
