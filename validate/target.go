package validate

import (
	"fmt"
	"reflect"

	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
	"github.com/go-playground/validator/v10"
)

func isTargetSupported(fl validator.FieldLevel) bool {
	field := fl.Field()

	switch field.Kind() {
	case reflect.String:
		_, ok := builder.BuilderByTarget[builder.Type(field.String())]
		return ok
	}

	panic(fmt.Sprintf("Bad field type %T", field.Interface()))
}
