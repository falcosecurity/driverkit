package validate

import (
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
	"github.com/go-playground/validator/v10"
	"reflect"
)

func isArchitectureSupported(fl validator.FieldLevel) bool {
	field := fl.Field()

	switch field.Kind() {
	case reflect.String:
		for _, arch := range builder.SupportedArchs {
			if arch == field.String() {
				return true
			}
		}
		return false
	}

	panic(fmt.Sprintf("Bad field type %T", field.Interface()))
}
