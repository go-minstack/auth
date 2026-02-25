package auth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

var jwksClient = &http.Client{Timeout: 10 * time.Second}

// loadRSAPublicFromJWKS fetches the first RSA key from a JWKS endpoint.
func loadRSAPublicFromJWKS(ctx context.Context, url string) (*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building JWKS request: %w", err)
	}

	res, err := jwksClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned %d", res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("reading JWKS response: %w", err)
	}

	var ks jwks
	if err := json.Unmarshal(body, &ks); err != nil {
		return nil, fmt.Errorf("parsing JWKS: %w", err)
	}
	if len(ks.Keys) == 0 {
		return nil, errors.New("JWKS contains no keys")
	}

	k := ks.Keys[0]
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decoding JWKS n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decoding JWKS e: %w", err)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}

// loadRSAPublicFromFile reads an RSA public key from a PEM file.
func loadRSAPublicFromFile(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading public key file: %w", err)
	}
	return parseRSAPublicPEM(data)
}

// loadRSAPrivateFromFile reads an RSA private key from a PEM file.
func loadRSAPrivateFromFile(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading private key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("private key file contains no PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// fallback: try PKCS1
		k, err2 := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parsing private key (PKCS8: %v, PKCS1: %v)", err, err2)
		}
		return k, nil
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return rsaKey, nil
}

func parseRSAPublicPEM(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("public key file contains no PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA")
	}
	return rsaPub, nil
}

// cachePublicKeyPEM writes the public key to MINSTACK_JWT_PUBLIC_KEY path as a PEM
// file so future restarts can skip the JWKS fetch. Logs a warning on failure — never fatal.
func cachePublicKeyPEM(pub *rsa.PublicKey, log *slog.Logger) {
	path := os.Getenv("MINSTACK_JWT_PUBLIC_KEY")
	if path == "" {
		return
	}

	pemBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Warn("failed to marshal public key for caching", "err", err)
		return
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		log.Warn("failed to create directory for public key cache", "path", path, "err", err)
		return
	}

	f, err := os.Create(path)
	if err != nil {
		log.Warn("failed to create public key cache file", "path", path, "err", err)
		return
	}
	defer f.Close()

	if err := pem.Encode(f, &pem.Block{Type: "PUBLIC KEY", Bytes: pemBytes}); err != nil {
		log.Warn("failed to write public key cache file", "path", path, "err", err)
	}
}
