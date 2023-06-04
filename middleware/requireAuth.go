package middleware

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/wonyus/go-auth/initializers"
	"github.com/wonyus/go-auth/models"
)

func RequireAuth(c *gin.Context) {
	accessTokenString, err := c.Cookie("AccessToken")
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	accessToken, err := jwt.Parse(accessTokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(os.Getenv("SECRET")), nil
	})

	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	if claims, ok := accessToken.Claims.(jwt.MapClaims); ok && accessToken.Valid {

		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		var user models.User
		initializers.DB.First(&user, claims["sub"])

		c.Set("user", user)
		c.Next()

	} else {
		fmt.Println(err)
	}

}

func CheckRefresh(c *gin.Context) {
	refreshTokenString, err := c.Cookie("RefreshToken")

	if err != nil {
		bearer := c.GetHeader("Authorization")
		if len(bearer) > 0 {
			refreshTokenString = strings.Split(bearer, " ")[1]
			err = nil
		}
	}

	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	refreshToken, err := jwt.Parse(refreshTokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(os.Getenv("SECRET")), nil
	})

	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	if claims, ok := refreshToken.Claims.(jwt.MapClaims); ok && refreshToken.Valid {

		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		var user models.User
		initializers.DB.First(&user, claims["sub"])

		c.Set("user", user)
		c.Next()

	} else {
		fmt.Println(err)
	}

}
