package initializers

import "github.com/wonyus/go-auth/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}
