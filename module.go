package auth

import (
	"context"
	"log/slog"

	"go.uber.org/fx"
)

// Module registers *JwtService into the FX dependency graph.
// Keys are loaded from environment variables during the OnStart lifecycle hook.
//
// Required env vars (one of):
//
//	MINSTACK_JWT_PRIVATE_KEY  — path to RSA private key PEM (enables Sign + Validate)
//	MINSTACK_JWKS_URL         — JWKS endpoint (enables Validate only; falls back to MINSTACK_JWT_PUBLIC_KEY)
//	MINSTACK_JWT_PUBLIC_KEY   — path to RSA public key PEM (enables Validate only)
//	MINSTACK_JWT_SECRET       — HMAC secret string (⚠ not recommended for production)
func Module() fx.Option {
	return fx.Provide(newJwtService)
}

func newJwtService(lc fx.Lifecycle, log *slog.Logger) *JwtService {
	svc := &JwtService{log: log}

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			return svc.loadKeys(ctx)
		},
	})

	return svc
}
