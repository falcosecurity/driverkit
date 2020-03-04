package validate

import (
	"fmt"
	"reflect"
	"regexp"

	"github.com/go-playground/validator/v10"
)

var sha1Regex = regexp.MustCompile("^[a-z0-9]{7,40}$")

func isSHA1(fl validator.FieldLevel) bool {
	field := fl.Field()

	switch field.Kind() {
	case reflect.String:
		return sha1Regex.MatchString(field.String())
	}

	panic(fmt.Sprintf("Bad field type %T", field.Interface()))
}
