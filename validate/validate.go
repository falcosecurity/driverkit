package validate

import (
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
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

	// Register a function to get the field name from "name" tags.
	V.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("name"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})

	V.RegisterValidation("loglevel", isLogLevel)
	V.RegisterValidation("filepath", isFilePath)
	V.RegisterValidation("sha1", isSHA1)
	V.RegisterValidation("target", isTargetSupported)
	V.RegisterValidation("architecture", isArchitectureSupported)
	V.RegisterValidation("semver", isSemVer)
	V.RegisterValidation("semvertolerant", isSemVerTolerant)
	V.RegisterValidation("proxy", isProxy)
	V.RegisterValidation("imagename", isImageName)

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
			t, _ := ut.T("filepath", fe.Field())

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
		"architecture",
		T,
		func(ut ut.Translator) error {
			return ut.Add("architecture", fmt.Sprintf("{0} must be a valid architecture (%s)", kernelrelease.SupportedArchs.String()), true)
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
			return ut.Add("required_kernelconfigdata_with_target_vanilla", "{0} is a required field when target is vanilla/minikube/flatcar", true)
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
			return ut.Add("required_kernelversion_with_target_ubuntu", "{0} is a required field when target is ubuntu", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("required_kernelversion_with_target_ubuntu", "kernel version") // fixme ? tag "name" does not work when used at struct level

			return t
		},
	)

	V.RegisterTranslation(
		"required_builderimage_with_target_redhat",
		T,
		func(ut ut.Translator) error {
			return ut.Add("required_builderimage_with_target_redhat", "{0} is a required field when target is redhat", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("required_builderimage_with_target_redhat", "builder image") // fixme ? tag "name" does not work when used at struct level

			return t
		},
	)

	V.RegisterTranslation(
		"loglevel",
		T,
		func(ut ut.Translator) error {
			return ut.Add("loglevel", "{0} must be a valid slog level", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("loglevel", fe.Field())

			return t
		},
	)

	V.RegisterTranslation(
		"eq=dev|sha1|semver",
		T,
		func(ut ut.Translator) error {
			return ut.Add("eq=dev|sha1|semver", `{0} must be a valid SHA1, semver-ish, or the "master" string`, true)
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
		"required_without",
		T,
		func(ut ut.Translator) error {
			return ut.Add("required_without", "{0} is required when {1} is missing", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T(fe.Tag(), fe.Field(), strings.ToLower(fe.Param()))

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

	V.RegisterTranslation(
		"proxy",
		T,
		func(ut ut.Translator) error {
			return ut.Add("proxy", "{0} must start with http:// or https:// or socks5:// prefix", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T(fe.Tag(), fe.Field(), fe.Param())

			return t
		},
	)
}
