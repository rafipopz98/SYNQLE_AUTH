package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID           primitive.ObjectID `bson:"_id,omitempty"`
	Username     string             `bson:"username,unique"`
	Email        string             `bson:"email,unique"`
	Password     string             `bson:"password"`
	Token        string             `bson:"token,omitempty"`
	RefreshToken string             `bson:"refresh_token,omitempty"`
	CreatedAt    time.Time          `bson:"created_at,omitempty"`
	UpdatedAt    time.Time          `bson:"updated_at,omitempty"`
}
