package utils

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/wonyus/go-auth/models"
)

func GenerateAccessToken(user models.User) (string, error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Minute * 15).Unix(),
	})

	accessTokenString, err := accessToken.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		return "", err
	}
	return accessTokenString, nil
}

// testt deploy
func GenerateRefreshToken(user models.User) (string, error) {
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})

	refreshTokenString, err := refreshToken.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		return "", err
	}
	return refreshTokenString, nil
}
