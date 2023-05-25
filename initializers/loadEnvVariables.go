package initializers

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
)

func LoadEnvVariables() {
	err := godotenv.Load(".prod.env")
	fmt.Println(os.Getenv("DB1"))
	if err != nil {
		log.Fatal("Error Loading .env file", err)
	}
}
