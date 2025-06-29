package validation

import (
	"errors"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
)

func ParseValidationErrors(err error, input interface{}) map[string]string {
	errorsMap := make(map[string]string)

	var validationErrors validator.ValidationErrors
	if !errors.As(err, &validationErrors) {
		errorsMap["message"] = err.Error()
		return errorsMap
	}

	inputType := reflect.TypeOf(input)
	if inputType.Kind() == reflect.Ptr {
		inputType = inputType.Elem()
	}

	for _, fe := range validationErrors {
		jsonField := toSnakeCase(fe.Field()) // default fallback

		if field, ok := inputType.FieldByName(fe.StructField()); ok {
			tag := field.Tag.Get("json")
			if tag != "" && tag != "-" {
				jsonField = strings.Split(tag, ",")[0]
			}
		}

		errorsMap[jsonField] = defaultErrorMessage(fe)
	}

	return errorsMap
}

func defaultErrorMessage(fieldErr validator.FieldError) string {
	switch fieldErr.Tag() {
	case "required":
		return "This field is required"
	case "email":
		return "Email is not valid"
	case "min":
		return "Must be at least " + fieldErr.Param() + " characters"
	case "eqfield":
		return "Must match " + fieldErr.Param()
	case "name":
		return "Name format is invalid"
	case "nohp":
		return "Phone number format is invalid"
	default:
		return "Invalid value"
	}
}

func toSnakeCase(s string) string {
	var result []rune
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result = append(result, '_')
		}
		result = append(result, r)
	}
	return strings.ToLower(string(result))
}
