package initializers

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
)

func LoadEnvVariables() {
	err := godotenv.Load()
	fmt.Println(os.Getenv("PORT"))
	if err != nil {
		log.Fatal("Error Loading .env file", err)
	}
}
