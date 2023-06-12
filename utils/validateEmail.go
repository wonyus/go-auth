package utils

import (
	"regexp"
)

func ValidateEmail(email string) bool {
	// Regular expression pattern for validating email addresses
	// This pattern is a simplified version and may not cover all edge cases
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`

	// Compile the regular expression pattern
	regex := regexp.MustCompile(pattern)

	// Use the MatchString method to check if the email matches the pattern
	return regex.MatchString(email)
}
