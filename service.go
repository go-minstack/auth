package auth

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JwtService signs and validates JWTs.
// Supports RSA (RS256) when keys are configured, or HMAC (HS256) as a fallback.
type JwtService struct {
	privateKey *rsa.PrivateKey // RSA: used for signing
	publicKey  *rsa.PublicKey  // RSA: used for validation
	secret     []byte          // HMAC: used for both signing and validation
	log        *slog.Logger
}

type jwtClaims struct {
	Name  string   `json:"name,omitempty"`
	Roles []string `json:"roles,omitempty"`
	jwt.RegisteredClaims
}

// loadKeys reads environment variables and populates the service's key fields.
// Priority:
//  1. MINSTACK_JWT_PRIVATE_KEY — RSA private key (public key derived automatically)
//  2. MINSTACK_JWKS_URL — fetch RSA public key from JWKS endpoint
//  3. MINSTACK_JWT_PUBLIC_KEY — RSA public key from PEM file (fallback after JWKS)
//  4. MINSTACK_JWT_SECRET — HMAC secret (last resort, not recommended)
func (s *JwtService) loadKeys(ctx context.Context) error {
	// 1. RSA private key
	if path := os.Getenv("MINSTACK_JWT_PRIVATE_KEY"); path != "" {
		priv, err := loadRSAPrivateFromFile(path)
		if err != nil {
			return fmt.Errorf("MINSTACK_JWT_PRIVATE_KEY: %w", err)
		}
		s.privateKey = priv
		s.publicKey = &priv.PublicKey
		s.log.Debug("auth: loaded RSA private key", "path", path)
		return nil
	}

	// 2. JWKS URL → RSA public key (verify-only)
	if url := os.Getenv("MINSTACK_JWKS_URL"); url != "" {
		pub, err := loadRSAPublicFromJWKS(ctx, url)
		if err != nil {
			s.log.Warn("auth: failed to load key from JWKS, trying file fallback", "url", url, "err", err)
		} else {
			s.publicKey = pub
			s.log.Debug("auth: loaded RSA public key from JWKS", "url", url)
			cachePublicKeyPEM(pub, s.log)
			return nil
		}
	}

	// 3. RSA public key from PEM file
	if path := os.Getenv("MINSTACK_JWT_PUBLIC_KEY"); path != "" {
		pub, err := loadRSAPublicFromFile(path)
		if err != nil {
			return fmt.Errorf("MINSTACK_JWT_PUBLIC_KEY: %w", err)
		}
		s.publicKey = pub
		s.log.Debug("auth: loaded RSA public key from file", "path", path)
		return nil
	}

	// 4. HMAC secret
	if secret := os.Getenv("MINSTACK_JWT_SECRET"); secret != "" {
		s.secret = []byte(secret)
		s.log.Warn("auth: using HMAC secret — RSA keys are recommended for production")
		return nil
	}

	return errors.New("no JWT key configured: set MINSTACK_JWT_PRIVATE_KEY, MINSTACK_JWKS_URL, MINSTACK_JWT_PUBLIC_KEY, or MINSTACK_JWT_SECRET")
}

// Sign creates a signed JWT for the given claims with the specified expiry.
// Requires MINSTACK_JWT_PRIVATE_KEY (RSA) or MINSTACK_JWT_SECRET (HMAC).
func (s *JwtService) Sign(claims Claims, expiry time.Duration) (string, error) {
	jc := jwtClaims{
		Name:  claims.Name,
		Roles: claims.Roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   claims.Subject,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	if s.privateKey != nil {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jc)
		return token.SignedString(s.privateKey)
	}

	if len(s.secret) > 0 {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jc)
		return token.SignedString(s.secret)
	}

	return "", errors.New("no signing key available: set MINSTACK_JWT_PRIVATE_KEY or MINSTACK_JWT_SECRET")
}

// Validate parses and validates a JWT string, returning the extracted Claims.
func (s *JwtService) Validate(tokenStr string) (*Claims, error) {
	var keyFunc jwt.Keyfunc

	if s.publicKey != nil {
		keyFunc = func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return s.publicKey, nil
		}
	} else if len(s.secret) > 0 {
		keyFunc = func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return s.secret, nil
		}
	} else {
		return nil, errors.New("no verification key available")
	}

	token, err := jwt.ParseWithClaims(tokenStr, &jwtClaims{}, keyFunc)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	jc, ok := token.Claims.(*jwtClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	return &Claims{
		Subject: jc.RegisteredClaims.Subject,
		Name:    jc.Name,
		Roles:   jc.Roles,
	}, nil
}
