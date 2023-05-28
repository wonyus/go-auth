package initializers

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
)

func LoadEnvVariables() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file:", err)
	}
	appMode := os.Getenv("APP_MODE")

	if appMode == "development" {
		err := godotenv.Load()
		if err != nil {
			log.Fatal("Error loading .env file:", err)
		}
	} else {
		err := godotenv.Load(".prod.env")
		if err != nil {
			log.Fatal("Error loading .env file:", err)
		}
	}
}
