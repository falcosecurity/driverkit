package validate

import (
	"github.com/go-playground/validator/v10"
	"log/slog"
)

var ProgramLevel = new(slog.LevelVar)

func isLogLevel(fl validator.FieldLevel) bool {
	level := fl.Field().Bytes()
	err := ProgramLevel.UnmarshalText(level)
	if err != nil {
		return false
	}
	return true
}
