package validate

import (
	logger "github.com/sirupsen/logrus"
	"reflect"
	"strings"

	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	en_translations "github.com/go-playground/validator/v10/translations/en"
)

// V is the validator single instance.
//
// It is a singleton so to cache the structs info.
var V *validator.Validate

// T is the universal translator for validatiors.
var T ut.Translator

func init() {
	V = validator.New()

	// Register a function to get the field name from "name" tags.
	V.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("name"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})

	V.RegisterValidation("logrus", func(fl validator.FieldLevel) bool {
		level := fl.Field().String()
		lvl, err := logger.ParseLevel(level)
		if err != nil {
			return false
		}
		logger.SetLevel(lvl)
		return true
	})

	eng := en.New()
	uni := ut.New(eng, eng)
	T, _ = uni.GetTranslator("en") // todo > see uni.FindTranslator(...) // todo ? handle the error
	en_translations.RegisterDefaultTranslations(V, T)

	V.RegisterTranslation(
		"file",
		T,
		func(ut ut.Translator) error {
			return ut.Add("file", "{0} must be a valid and existing file", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("file", fe.Field())

			return t
		},
	)

	V.RegisterTranslation(
		"required_kernelconfigdata_with_target_vanilla",
		T,
		func(ut ut.Translator) error {
			return ut.Add("required_kernelconfigdata_with_target_vanilla", "{0} is a required field when target is vanilla", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("required_kernelconfigdata_with_target_vanilla", "kernel config data") // fixme ? tag "name" does not work when used at struct level

			return t
		},
	)

	V.RegisterTranslation(
		"logrus",
		T,
		func(ut ut.Translator) error {
			return ut.Add("logrus", "{0} must be a valid logrus level", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("logrus", fe.Field())

			return t
		},
	)

}
