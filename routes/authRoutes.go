package routes

import (
	"auth-service/controllers"
	"auth-service/middleware"

	"github.com/gorilla/mux"
)

func RegisterAuthRoutes(r *mux.Router) {
	r.HandleFunc("/api/signup", controllers.SignUpHandler).Methods("POST")
	r.HandleFunc("/api/login", controllers.LoginHandler).Methods("POST")
	r.HandleFunc("/api/refresh", controllers.RefreshTokenHandler).Methods("POST")
	r.HandleFunc("/api/logout", controllers.LogoutHandler).Methods("POST")


	protected := r.PathPrefix("/api").Subrouter()
	protected.Use(middleware.IsAuthUser)
	protected.HandleFunc("/user", controllers.GetUserHandler).Methods("GET")
}
