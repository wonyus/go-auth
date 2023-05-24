package utils

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/wonyus/go-auth/initializers"
	"github.com/wonyus/go-auth/models"
)

func GetUserFromJWT(c *gin.Context) (models.User, error) {
	tokenString, _ := c.Cookie("RefreshToken")
	var user models.User

	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return user, err
	}

	initializers.DB.First(&user, claims["sub"])

	return user, nil
}
