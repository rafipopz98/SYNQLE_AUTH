package middleware

import (
	"context"
	"net/http"

	"auth-service/utils"
)

func IsAuthUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("accessUserToken")
		if err != nil {
			if err == http.ErrNoCookie {
				http.Error(w, "Missing or invalid cookie", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Error retrieving cookie", http.StatusUnauthorized)
			return
		}

		tokenString := cookie.Value

		claims, err := utils.ParseJWT(tokenString)
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Attach user information to context (optional)
		ctx := context.WithValue(r.Context(), "user", claims)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}
