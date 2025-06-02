package main

import (
	"cli-chat-app/database"
	"context"
	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"log"
)

var userCollection *mongo.Collection

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}
func main() {
	// Connect to MongoDB
	err := database.ConnectToDataBase()
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer database.Client.Disconnect(context.TODO())

	app := fiber.New()
	// Global error recovery (optional)
	app.Use(func(c *fiber.Ctx) error {
		defer func() {
			if r := recover(); r != nil {
				log.Println("Recovered in middleware:", r)
				c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"success": false,
					"error":   "Internal Server Error",
				})
			}
		}()
		return c.Next()
	})

	// Routes
	app.Post("/register", RegisterUser)
	app.Post("/login", LoginUser)

	// Protected route
	app.Get("/validate", JWTMiddleware, ValidateTokenHandler)
	app.Post("/send-message", JWTMiddleware, SendMessage)
	app.Get("/get-messages", JWTMiddleware, GetMessages)
	app.Put("/mark-message-read/:id", JWTMiddleware, MarkMessageAsRead)
	app.Post("/friend-request/send", JWTMiddleware, SendFriendRequest)
	app.Post("/friend-request/respond", JWTMiddleware, RespondFriendRequest)

	log.Println("Server running on http://localhost:8000")
	if err := app.Listen(":8000"); err != nil {
		log.Fatal(err)
	}
}
