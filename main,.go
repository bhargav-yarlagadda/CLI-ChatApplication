package main

import (
	"cli-chat-app/database"
	"context"
	"log"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/mongo"
)

var userCollection *mongo.Collection

func main() {
	// Connect to MongoDB
	 err := database.ConnectToDataBase()
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer database.Client.Disconnect(context.TODO())

	app := fiber.New()

	// Routes
	app.Post("/register", RegisterUser)
	app.Post("/login", LoginUser)

	// Protected route
	app.Get("/validate", JWTMiddleware, ValidateTokenHandler)
	log.Println("Server running on http://localhost:8000")
	if err := app.Listen(":8000"); err != nil {
		log.Fatal(err)
	}
}
