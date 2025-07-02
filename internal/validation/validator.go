package validation

import (
	"regexp"

	"github.com/go-playground/validator/v10"
)

var Validate *validator.Validate

func InitValidator() {
	Validate = validator.New()

	// Custom "name" validation
	_ = Validate.RegisterValidation("name", func(fl validator.FieldLevel) bool {
		return len(fl.Field().String()) >= 2 // Example rule
	})

	// Custom "nohp" (e.g., phone number) validation
	_ = Validate.RegisterValidation("nohp", func(fl validator.FieldLevel) bool {
		regex := regexp.MustCompile(`^\+?[\d\s\-]{9,15}$`)
		return regex.MatchString(fl.Field().String())
	})
}
