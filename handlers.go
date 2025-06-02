package main

import (
	"cli-chat-app/database"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret = []byte("4f8d9a2c7b1e5f3d9c6a8b7e4d1f2a3c5e7b9d8f1a2c3e4f5b6d7c8e9f0a1b2c")

func RegisterUser(c *fiber.Ctx) error {
	type RequestBody struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	var body RequestBody
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success":false,

			"error": "Invalid request. Username and password are required.",
		})
	}

	if body.Username == "" || body.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success":false,

			"error": "Username and password cannot be empty.",
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// ✅ Get DB and Collection
	db := database.Client.Database(os.Getenv("USER_DB"))
	usersCol := db.Collection(os.Getenv("USER_COL"))

	// ✅ Check if user already exists
	var existingUser bson.M
	err := usersCol.FindOne(ctx, bson.M{"username": body.Username}).Decode(&existingUser)
	if err == nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"success":false,

			"error": "Username already exists.",
		})
	}

	// ✅ Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success":false,

			"error": "Password hashing failed.",
		})
	}

	// ✅ Generate ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success":false,

			"error": "Key generation failed.",
		})
	}

	// ✅ Insert user into database
	userDoc := bson.M{
		"username":   body.Username,
		"password":   string(hashedPassword),
		"publicKey":  hex.EncodeToString(pubKey),
		"created_at": time.Now(),
	}

	_, err = usersCol.InsertOne(ctx, userDoc)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success":false,
			"error": "Failed to create user.",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"success":true,

		"message":    "User registered successfully.",
		"publicKey":  hex.EncodeToString(pubKey),
		"privateKey": hex.EncodeToString(privKey),
	})
}

func LoginUser(c *fiber.Ctx) error {
	type RequestBody struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	var body RequestBody
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success":false,
			"error": "Invalid request. Username and password are required.",
		})
	}

	if body.Username == "" || body.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success":false,

			"error": "Username and password cannot be empty.",
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db := database.Client.Database(os.Getenv("USER_DB"))
	usersCol := db.Collection(os.Getenv("USER_COL"))

	var userDoc struct {
		Username  string `bson:"username"`
		Password  string `bson:"password"`
		PublicKey string `bson:"publicKey"`
	}

	err := usersCol.FindOne(ctx, bson.M{"username": body.Username}).Decode(&userDoc)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"success":false,

			"error": "Invalid username or password.",
		})
	}

	err = bcrypt.CompareHashAndPassword([]byte(userDoc.Password), []byte(body.Password))
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"success":false,

			"error": "Invalid username or password.",
		})
	}

	// Generate JWT token on successful login
	claims := JwtCustomClaims{
		Username:  userDoc.Username,
		PublicKey: userDoc.PublicKey,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)), // token expires in 24 hours
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "cli-chat-app",
			Subject:   userDoc.Username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(jwtSecret)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success":false,
			"error": "Failed to generate token.",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"success":true,

		"message":   "Login successful.",
		"token":     signedToken,
		"publicKey": userDoc.PublicKey,
	})
}

func ValidateTokenHandler(c *fiber.Ctx) error {
	claims := c.Locals("user")
	if claims == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"success":false,
			"error": "No user info found in token",
		})
	}

	return c.JSON(fiber.Map{
		"success":true,
		"message": "Token is valid",
		"user":    claims,
	})
}
func SendMessage(c *fiber.Ctx) error {
	var body struct {
		Receiver string `json:"receiver"`
		Message  string `json:"message"`
	}
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"error":   "Invalid request body",
		})
	}

	if body.Receiver == "" || body.Message == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"error":   "Receiver and message must be provided",
		})
	}

	claims := c.Locals("user").(jwt.MapClaims)
	sender := claims["username"].(string)

	if sender == body.Receiver {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"error":   "Cannot send message to yourself",
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	friendReqCol := database.Client.Database(os.Getenv("USER_DB")).Collection(os.Getenv("FRIEND_RELATIONS"))

	// Check if sender and receiver are friends (status == "accepted")
	count, err := friendReqCol.CountDocuments(ctx, bson.M{
		"$or": []bson.M{
			{"from": sender, "to": body.Receiver, "status": "accepted"},
			{"from": body.Receiver, "to": sender, "status": "accepted"},
		},
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"error":   "Database error while checking friendship",
		})
	}

	if count == 0 {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"success": false,
			"error":   "Cannot send message. You are not friends with the recipient",
		})
	}

	// Proceed to insert the message
	messageDoc := bson.M{
		"from":      sender,
		"to":        body.Receiver,
		"content":   body.Message,
		"read":      false,
		"timestamp": time.Now(),
	}

	msgCol := database.Client.Database(os.Getenv("USER_DB")).Collection(os.Getenv("MESSAGES_DB"))
	_, err = msgCol.InsertOne(ctx, messageDoc)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to send message",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"success": true,
		"message": "Message sent successfully",
	})
}



func GetMessages(c *fiber.Ctx) error {
	claims := c.Locals("user").(jwt.MapClaims)
    username := claims["username"].(string)


	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	msgCol := database.Client.Database(os.Getenv("USER_DB")).Collection(os.Getenv("MESSAGES_DB"))

	cursor, err := msgCol.Find(ctx, bson.M{
		"$or": []bson.M{
			{"from": username},
			{"to": username},
		},
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to retrieve messages",
		})
	}
	defer cursor.Close(ctx)

	var messages []Message
	if err := cursor.All(ctx, &messages); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"error":   "Error while decoding messages",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"success":  true,
		"messages": messages,
	})
}
func MarkMessageAsRead(c *fiber.Ctx) error {
	messageID := c.Params("id")
	if messageID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"error":   "Message ID is required",
		})
	}

	objID, err := primitive.ObjectIDFromHex(messageID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"error":   "Invalid message ID format",
		})
	}

	// Get logged-in user (receiver)
	claims := c.Locals("user").(jwt.MapClaims)
	username := claims["username"].(string)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	msgCol := database.Client.Database(os.Getenv("USER_DB")).Collection(os.Getenv("MESSAGES_DB"))

	// Ensure the logged-in user is the receiver
	filter := bson.M{"_id": objID, "to": username}
	update := bson.M{"$set": bson.M{"read": true}}

	result, err := msgCol.UpdateOne(ctx, filter, update)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to mark message as read",
		})
	}

	if result.MatchedCount == 0 {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"success": false,
			"error":   "You are not authorized to mark this message as read",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"success": true,
		"message": "Message marked as read",
	})
}


func SendFriendRequest(c *fiber.Ctx) error {
	type RequestBody struct {
		To string `json:"to"`
	}

	var body RequestBody
	if err := c.BodyParser(&body); err != nil || body.To == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"error":   "Recipient username is required",
		})
	}

	claims := c.Locals("user").(jwt.MapClaims)
	from := claims["username"].(string)

	if from == body.To {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"error":   "Cannot send friend request to yourself",
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db := database.Client.Database(os.Getenv("USER_DB"))
	usersCol := db.Collection(os.Getenv("USER_COL"))
	friendReqCol := db.Collection(os.Getenv("FRIEND_RELATIONS"))

	// Check if 'to' user exists
	var toUser struct {
		Username  string `bson:"username"`
		PublicKey string `bson:"publicKey"`
	}
	err := usersCol.FindOne(ctx, bson.M{"username": body.To}).Decode(&toUser)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"success": false,
			"error":   "Recipient user not found",
		})
	}

	// Check if friend request or friendship already exists
	count, err := friendReqCol.CountDocuments(ctx, bson.M{
		"$or": []bson.M{
			{"from": from, "to": body.To},
			{"from": body.To, "to": from},
		},
		"status": bson.M{"$in": []string{"pending", "accepted"}},
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"error":   "Database error",
		})
	}
	if count > 0 {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"success": false,
			"error":   "Friend request already sent or you are already friends",
		})
	}

	// Get sender public key
	var fromUser struct {
		Username  string `bson:"username"`
		PublicKey string `bson:"publicKey"`
	}
	err = usersCol.FindOne(ctx, bson.M{"username": from}).Decode(&fromUser)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"error":   "Sender user not found",
		})
	}

	// Insert friend request
	reqDoc := bson.M{
		"from":            from,
		"to":              body.To,
		"from_public_key": fromUser.PublicKey,
		"to_public_key":   toUser.PublicKey,
		"status":          "pending",
		"created_at":      time.Now(),
		"updated_at":      time.Now(),
	}

	_, err = friendReqCol.InsertOne(ctx, reqDoc)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to send friend request",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"success": true,
		"message": "Friend request sent",
	})
}

func RespondFriendRequest(c *fiber.Ctx) error {
	type RequestBody struct {
		RequestID string `json:"request_id"`
		Accept    bool   `json:"accept"`
	}

	var body RequestBody
	if err := c.BodyParser(&body); err != nil || body.RequestID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"error":   "Request ID and accept status are required",
		})
	}

	objID, err := primitive.ObjectIDFromHex(body.RequestID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"error":   "Invalid request ID format",
		})
	}

	claims := c.Locals("user").(jwt.MapClaims)
	username := claims["username"].(string)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	friendReqCol := database.Client.Database(os.Getenv("USER_DB")).Collection(os.Getenv("FRIEND_RELATIONS"))

	// Find the friend request
	var friendReq FriendRequest
	err = friendReqCol.FindOne(ctx, bson.M{"_id": objID, "to": username, "status": "pending"}).Decode(&friendReq)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"success": false,
			"error":   "Friend request not found or already responded",
		})
	}

	newStatus := "rejected"
	if body.Accept {
		newStatus = "accepted"
	}

	_, err = friendReqCol.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{
		"$set": bson.M{
			"status":     newStatus,
			"updated_at": time.Now(),
		},
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"error":   "Failed to update friend request",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"success": true,
		"message": "Friend request " + newStatus,
	})
}
