package main

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type User struct {
	ID         string `json:"id,omitempty" bson:"_id,omitempty"`
	Username   string `json:"username" bson:"username"`
	Password   string `json:"password" bson:"password"`
	Public_Key string `json:"public_key" bson:"public_key"`
}

type Message struct {
	ID        string    `json:"id,omitempty" bson:"_id,omitempty"`
	From      string    `json:"from" bson:"from"`
	To        string    `json:"to" bson:"to"`
	Content   string    `json:"content" bson:"content"`
	Read      bool      `json:"read" bson:"read"`
	Timestamp time.Time `json:"timestamp" bson:"timestamp"`
}

type JwtCustomClaims struct {
	Username  string `json:"username"`
	PublicKey string `json:"publicKey"`
	jwt.RegisteredClaims
}
type FriendRequest struct {
    ID             string    `json:"id,omitempty" bson:"_id,omitempty"`
    From           string    `json:"from"`           // UserID or username of requester
    To             string    `json:"to"`             // UserID or username of recipient
    FromPublicKey  string    `json:"from_public_key"` // Requester's public key (for E2EE)
    ToPublicKey    string    `json:"to_public_key"`   // Recipient's public key (for E2EE)
    Status         string    `json:"status"`          // "pending", "accepted", "rejected"
    CreatedAt      time.Time `json:"created_at"`
    UpdatedAt      time.Time `json:"updated_at"`
}
