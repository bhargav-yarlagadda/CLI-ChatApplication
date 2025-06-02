package main

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type User struct {
	Username   string
	Password   string
	Public_Key string
}
type Message struct {
	From    string
	To      string
	Content string
	Read    bool
	Timestamp time.Time
}

type JwtCustomClaims struct {
	Username  string `json:"username"`
	PublicKey string `json:"publicKey"`
	jwt.RegisteredClaims
}
