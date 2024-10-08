package main

import (
	"auth-service/routes"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

func init() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

func main() {

	port := os.Getenv("PORT")
	if port == "" {
		port = "8079"
	}

	r := mux.NewRouter()
	routes.RegisterAuthRoutes(r)

	log.Println("Server starting on port " + port + "...")
	http.ListenAndServe(":"+port, r)

}