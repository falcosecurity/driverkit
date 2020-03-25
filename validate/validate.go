package validate

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
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

	V.RegisterAlias("dev_or_sha1_or_semver", "eq=dev|sha1|semver")
	
	// Register a function to get the field name from "name" tags.
	V.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("name"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})

	V.RegisterValidation("logrus", isLogrusLevel)
	V.RegisterValidation("filepath", isFilePath)
	V.RegisterValidation("sha1", isSHA1)
	V.RegisterValidation("target", isTargetSupported)
	V.RegisterValidation("semver", isSemVer)

	eng := en.New()
	uni := ut.New(eng, eng)
	T, _ = uni.GetTranslator("en")
	en_translations.RegisterDefaultTranslations(V, T)

	V.RegisterTranslation(
		"filepath",
		T,
		func(ut ut.Translator) error {
			return ut.Add("filepath", "{0} must be a valid file path", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T(fe.Tag(), fe.Field())

			return t
		},
	)

	V.RegisterTranslation(
		"target",
		T,
		func(ut ut.Translator) error {
			return ut.Add("target", fmt.Sprintf("{0} must be a valid target (%s)", builder.BuilderByTarget.Targets()), true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T(fe.Tag(), fe.Field())

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
		"required_kernelversion_with_target_ubuntu",
		T,
		func(ut ut.Translator) error {
			return ut.Add("required_kernelversion_with_target_ubuntu", "{0} is a required field when target is ubuntu-generic or ubuntu-aws", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("required_kernelversion_with_target_ubuntu", "kernel version") // fixme ? tag "name" does not work when used at struct level

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

	V.RegisterTranslation(
		"dev_or_sha1_or_semver",
		T,
		func(ut ut.Translator) error {
			return ut.Add("dev_or_sha1_or_semver", `{0} must be a valid SHA1, semver-ish, or the "dev" string`, true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T(fe.Tag(), fe.Field())

			return t
		},
	)

	V.RegisterTranslation(
		"semver",
		T,
		func(ut ut.Translator) error {
			return ut.Add("semver", "{0} must be a semver-ish string", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T(fe.Tag(), fe.Field())

			return t
		},
	)

	V.RegisterTranslation(
		"atleast_an_output_path",
		T,
		func(ut ut.Translator) error {
			return ut.Add("atleast_an_output_path", "{0}at least one output path is required ({1})", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T(fe.Tag(), fe.Field(), fe.Param())

			return t
		},
	)

	V.RegisterTranslation(
		"admitted_only_with_target_vanilla",
		T,
		func(ut ut.Translator) error {
			return ut.Add("admitted_only_with_target_vanilla", "{0} is allowed only when target is vanilla", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T(fe.Tag(), fe.Field())

			return t
		},
	)

	V.RegisterTranslation(
		"endswith",
		T,
		func(ut ut.Translator) error {
			return ut.Add("endswith", "{0} must end with {1}", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T(fe.Tag(), fe.Field(), fe.Param())

			return t
		},
	)
}