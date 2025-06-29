package validation

import (
	"github.com/go-playground/validator/v10"
)

func ParseValidationErrors(err error) map[string]string {
	errors := make(map[string]string)

	if err == nil {
		return errors
	}

	// Only handle validator.ValidationErrors
	if validationErrors, ok := err.(validator.ValidationErrors); ok {
		for _, fieldErr := range validationErrors {
			fieldName := fieldErr.Field()
			switch fieldErr.Tag() {
			case "required":
				errors[fieldName] = fieldName + " is required"
			case "email":
				errors[fieldName] = "Email is not valid"
			case "min":
				errors[fieldName] = fieldName + " must be at least " + fieldErr.Param() + " characters"
			case "eqfield":
				errors[fieldName] = fieldName + " must be equal to " + fieldErr.Param()
			case "name":
				errors[fieldName] = "Name format is invalid"
			case "nohp":
				errors[fieldName] = "Phone number format is invalid"
			default:
				errors[fieldName] = "Invalid value for " + fieldName
			}
		}
	} else {
		// fallback for unexpected error types
		errors["message"] = err.Error()
	}

	return errors
}
