package validate

import (
	"fmt"
	"reflect"

	"github.com/Masterminds/semver/v3"
	"github.com/go-playground/validator/v10"
)

func isSemVer(fl validator.FieldLevel) bool {
	field := fl.Field()

	switch field.Kind() {
	case reflect.String:
		_, err := semver.NewVersion(field.String())
		return err == nil
	}

	panic(fmt.Sprintf("Bad field type %T", field.Interface()))
}
