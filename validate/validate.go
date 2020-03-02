package validate

import (
	"github.com/go-playground/validator/v10"
)

// V is the validator single instance.
//
// It is a singleton so to cache the structs info.
var V *validator.Validate

func init() {
	V = validator.New()
}
