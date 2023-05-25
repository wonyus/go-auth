package initializers

import (
	"log"

	"github.com/joho/godotenv"
)

func LoadEnvVariables() {
	err := godotenv.Load(".env.prod")

	if err != nil {
		log.Fatal("Error Loading .env file")
	}
}
