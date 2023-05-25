package initializers

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

func LoadEnvVariables() {
	err := godotenv.Load()
	os.Getenv("PORT")
	if err != nil {
		log.Fatal("Error Loading .env file")
	}
}
