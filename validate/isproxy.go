package validate

import (
	"fmt"
	"reflect"
	"regexp"

	"github.com/go-playground/validator/v10"
)

var proxyRegex = regexp.MustCompile("^(http://|https://|socks5://)")

func isProxy(fl validator.FieldLevel) bool {
	field := fl.Field()

	switch field.Kind() {
	case reflect.String:
		return proxyRegex.MatchString(field.String())
	}

	panic(fmt.Sprintf("Bad field type %T", field.Interface()))
}
