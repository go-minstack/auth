package auth

import "github.com/gin-gonic/gin"

// Claims holds the data extracted from a validated JWT.
type Claims struct {
	Subject string
	Name    string
	Roles   []string
	Flatten map[string]any // flattened into JWT top-level claims when signing
}

const claimsKey = "x-claims"

// ClaimsFromContext returns the claims set by Authenticate, or false if not present.
func ClaimsFromContext(c *gin.Context) (*Claims, bool) {
	v, ok := c.Get(claimsKey)
	if !ok {
		return nil, false
	}
	claims, ok := v.(*Claims)
	return claims, ok
}
