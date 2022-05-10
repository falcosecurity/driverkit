package validate

import (
	"github.com/go-playground/validator/v10"
	"strings"
)

const letters = "abcdefghijklmnopqrstuvwxyz"
const digits = "0123456789"
const separators = "/.-@_:"
const alphabet = letters + digits + separators

func isImageName(fl validator.FieldLevel) bool {
	name := fl.Field().String()

	for _, c := range name {
		if !strings.ContainsRune(alphabet, c) {
			return false
		}
	}

	for _, component := range strings.Split(name, "/") {
		// a component may not be empty (i.e. double slashes are not allowed)
		if len(component) == 0 {
			return false
		}

		// a component may not start or end with a separator
		if strings.Contains(separators, component[0:1]) || strings.Contains(separators, component[len(component)-1:]) {
			return false
		}
	}

	return true
}
