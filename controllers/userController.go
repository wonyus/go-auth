package controllers

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/wonyus/go-auth/initializers"
	"github.com/wonyus/go-auth/models"
	"github.com/wonyus/go-auth/utils"
	"golang.org/x/crypto/bcrypt"
)

func Signup(c *gin.Context) {
	var body struct {
		Email    string
		Password string
		Name     string
		Username string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})

		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to hash password",
		})

		return
	}

	user := models.User{Email: body.Email, Password: string(hash), Name: body.Name, Username: body.Username}
	result := initializers.DB.Create((&user))

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create user",
		})

		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func Login(c *gin.Context) {
	var body struct {
		Username string
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})

		return
	}
	var user models.User
	initializers.DB.First(&user, "Username = ?", body.Username)

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid Username or Password",
		})

		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid Username or Password",
		})

		return
	}

	AccessTokenString, err := utils.GenerateAccessToken(user)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create token",
		})

		return
	}

	RefreshTokenString, err := utils.GenerateRefreshToken(user)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create token",
		})

		return
	}

	user.AccessToken = AccessTokenString
	user.RefreshToken = RefreshTokenString
	initializers.DB.Save(&user)

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("AccessToken", AccessTokenString, 900, "", "", false, true)
	c.SetCookie("RefreshToken", RefreshTokenString, 3600*24, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{"message": user})
}

func Logout(c *gin.Context) {
	tokenString, _ := c.Cookie("RefreshToken")

	type MyCustomClaims struct {
		Sub int64 `json:"sub"`
		jwt.RegisteredClaims
	}

	token, err := jwt.ParseWithClaims(tokenString, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})

	if claims, ok := token.Claims.(*MyCustomClaims); ok && token.Valid {
		var user models.User
		initializers.DB.First(&user, claims.Sub)
		user.AccessToken = "NULL"
		user.RefreshToken = "NULL"
		initializers.DB.Save(&user)

		c.SetCookie("AccessToken", "", -1, "", "", false, true)
		c.SetCookie("RefreshToken", "", -1, "", "", false, true)
		c.JSON(http.StatusOK, gin.H{})
	} else {
		fmt.Println(err)
	}

}

func GetUser(c *gin.Context) {
	tokenString, _ := c.Cookie("RefreshToken")

	type MyCustomClaims struct {
		Sub int64 `json:"sub"`
		jwt.RegisteredClaims
	}

	token, err := jwt.ParseWithClaims(tokenString, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})

	if claims, ok := token.Claims.(*MyCustomClaims); ok && token.Valid {
		var user models.User
		initializers.DB.First(&user, claims.Sub)

		c.JSON(http.StatusOK, gin.H{"message": user})
	} else {
		fmt.Println(err)
	}
}

func Refresh(c *gin.Context) {
	user, err := utils.GetUserFromJWT(c)

	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	AccessTokenString, err := utils.GenerateAccessToken(user)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create token",
		})

		return
	}

	RefreshTokenString, err := utils.GenerateRefreshToken(user)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create token",
		})

		return
	}
	user.AccessToken = AccessTokenString
	user.RefreshToken = RefreshTokenString
	initializers.DB.Save(&user)

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("AccessToken", AccessTokenString, 900, "", "", false, true)
	c.SetCookie("RefreshToken", RefreshTokenString, 3600*24, "", "", false, true)
	c.JSON(http.StatusOK, gin.H{"AccessToken": AccessTokenString, "RefreshToken": RefreshTokenString})
}

func ChangePassword(c *gin.Context) {
	var body struct {
		OldPassword string
		NewPassword string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})

		return
	}

	user, _ := utils.GetUserFromJWT(c)

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.OldPassword))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid Password",
		})

		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.NewPassword), 10)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to hash password",
		})

		return
	}

	user.Password = string(hash)
	initializers.DB.Save(&user)
	c.JSON(http.StatusOK, gin.H{
		"message": user,
	})
}

func Validate(c *gin.Context) {
	user, _ := c.Get("user")

	c.JSON(http.StatusOK, gin.H{
		"message": user,
	})
}
