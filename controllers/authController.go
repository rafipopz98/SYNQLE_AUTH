package controllers

import (
	database "auth-service/config"
	"auth-service/models"
	"auth-service/utils"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "User")

func SignUpHandler(w http.ResponseWriter, r *http.Request) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var user models.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if len(user.Username) < 2 || len(user.Username) > 100 {
		http.Error(w, "Username must be between 2 and 100 characters", http.StatusBadRequest)
		return
	}
	if !utils.IsValidEmail(user.Email) {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	var existingUser models.User
	filter := bson.M{
		"$or": []bson.M{
			{"username": user.Username},
			{"email": user.Email},
		},
	}
	err = userCollection.FindOne(ctx, filter).Decode(&existingUser)
	if err == nil {
		http.Error(w, "Username or email already exists", http.StatusConflict)
		return
	}

	hashedPassword, err := utils.HashPassword(user.Password)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}
	user.Password = hashedPassword

	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	result, err := userCollection.InsertOne(ctx, user)
	if err != nil {
		http.Error(w, "Error saving user", http.StatusInternalServerError)
		return
	}

	insertedID := result.InsertedID.(primitive.ObjectID)
	user.ID = insertedID

	token, err := utils.GenerateJWT(user.Username, user.Email)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "accessUserToken",
		Value:    token,
		HttpOnly: true,
		Secure:   false,
		Path:     "/",
	})

	response := map[string]string{
		"message":  "Signup successful",
		"token":    token,
		"id":       user.ID.Hex(),
		"username": user.Username,
		"email":    user.Email,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var loginRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&loginRequest)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var user models.User

	err = userCollection.FindOne(ctx, bson.M{"username": loginRequest.Username}).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	if !utils.CheckPasswordHash(loginRequest.Password, user.Password) {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	token, err := utils.GenerateJWT(user.Username, user.Email)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := utils.GenerateRefreshToken(user.ID.Hex())
	if err != nil {
		http.Error(w, "Error generating refresh token", http.StatusInternalServerError)
		return
	}

	// Update the user's refresh token in the database
	_, err = userCollection.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{"$set": bson.M{"refresh_token": refreshToken}})
	if err != nil {
		http.Error(w, "Error updating refresh token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "accessUserToken",
		Value:    token,
		HttpOnly: true,
		Secure:   false,
		Path:     "/",
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refreshUserToken",
		Value:    refreshToken,
		HttpOnly: true,
		Secure:   false,
		Path:     "/",
	})

	response := map[string]string{
		"message":       "Login successful",
		"token":         token,
		"refresh_token": refreshToken,
		"id":            user.ID.Hex(),
		"username":      user.Username,
		"email":         user.Email,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RefreshToken string `json:"refresh_token"`
	}

	var refreshToken string

	if err := json.NewDecoder(r.Body).Decode(&request); err == nil {
		refreshToken = request.RefreshToken
	} else {
		// If not found in the body, check cookies
		cookie, err := r.Cookie("refreshUserToken")
		if err == nil {
			refreshToken = cookie.Value
		} else {
			http.Error(w, "Refresh token not found", http.StatusUnauthorized)
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var user models.User
	err := userCollection.FindOne(ctx, bson.M{"refresh_token": refreshToken}).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	token, err := utils.GenerateJWT(user.Username, user.Email)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "accessUserToken",
		Value:    token,
		HttpOnly: true,
		Secure:   false,
		Path:     "/",
	})

	response := map[string]string{
		"token":   token,
		"message": "Token refreshed successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "accessUserToken",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteNoneMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refreshUserToken",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteNoneMode,
	})

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{"message": "User has been logged out successfully"}
	json.NewEncoder(w).Encode(response)
}

func GetUserHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("user").(*utils.Claims)
	if !ok {
		http.Error(w, "Unable to retrieve user from context", http.StatusUnauthorized)
		return
	}

	username := claims.Username
	var user models.User
	err := userCollection.FindOne(r.Context(), map[string]interface{}{"username": username}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"id":        user.ID.Hex(),
		"username":  user.Username,
		"email":     user.Email,
		"createdAt": user.CreatedAt,
		"updatedAt": user.UpdatedAt,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
