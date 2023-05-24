package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/wonyus/go-auth/utils"
	"go.uber.org/zap"
)

func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		utils.InitializeLogger()
		utils.Logger.Info("Info", zap.String("url", c.Request.Host+c.Request.URL.String()))
		c.Next()
	}

}
