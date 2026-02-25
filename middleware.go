package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type errorResponse struct {
	Error string `json:"error"`
}

// Authenticate is a gin middleware that validates the JWT from the Authorization header
// and stores the resulting Claims in the gin context for downstream handlers.
//
// On failure it aborts with 401 Unauthorized. Must run before RequireRole.
func Authenticate(s *JwtService) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, ok := bearerToken(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, errorResponse{"missing or malformed Authorization header"})
			return
		}

		claims, err := s.Validate(token)
		if err != nil {
			s.log.Debug("auth: token validation failed", "err", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, errorResponse{"unauthorized"})
			return
		}

		c.Set(claimsKey, claims)
		c.Next()
	}
}

// RequireRole is a gin middleware that checks the authenticated user has at least
// one of the specified roles. Must run after Authenticate.
//
// Returns 403 Forbidden if the user lacks the required role.
func RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := ClaimsFromContext(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, errorResponse{"unauthorized"})
			return
		}

		for _, required := range roles {
			for _, have := range claims.Roles {
				if strings.EqualFold(required, have) {
					c.Next()
					return
				}
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, errorResponse{"forbidden"})
	}
}

// bearerToken extracts the token from "Authorization: Bearer <token>".
// Returns false if the header is absent or the scheme is not Bearer.
func bearerToken(c *gin.Context) (string, bool) {
	header := c.GetHeader("Authorization")
	if header == "" {
		return "", false
	}

	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}

	return parts[1], true
}
