package database

import (
	"context"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var Client *mongo.Client

func ConnectToDataBase() error {
	uri := os.Getenv("MONGO_URI")

	if uri == "" {
		log.Fatal("MISSING ENVIRONMENT VARIABLE: MONGO_URI")
		return mongo.ErrClientDisconnected
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
		return err
	}

	// Ping the database
	if err := client.Ping(ctx, nil); err != nil {
		log.Fatalf("Failed to ping MongoDB: %v", err)
		return err
	}

	// ✅ Assign to global variable
	Client = client

	log.Println("Connected to MongoDB successfully")
	return nil
}
