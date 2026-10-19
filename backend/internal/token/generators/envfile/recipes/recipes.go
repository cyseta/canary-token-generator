// Package recipes genera bloques de variables de entorno senuelo.
//
// Todos los valores respetan el FORMATO REAL de cada credencial (alfabeto y longitud), porque los
// escaneres de secretos (trufflehog, gitleaks...) descartan lo que no encaja con su expresion regular y
// asi el senuelo jamas llegaria a ser "verificado" contra el servicio. Todo se deriva de la semilla del
// token, de forma independiente entre campos (antes algunos secretos eran un prefijo de otros).
package recipes

import (
	"fmt"

	"canary-token-generator/backend/internal/token/generators/seed"
)

// AWS: AKIA + 16 caracteres base32 mayusculas; secreto de 40 caracteres base64.
// AWS_ENDPOINT_URL es una variable REAL que respetan el AWS CLI v2 y los SDK modernos: si el atacante carga
// este .env y usa las claves, la peticion firmada llega a este servidor (y queda el Access Key ID en el evento).
func AWS(s *seed.Stream, endpoint string) []string {
	return []string{
		"# AWS credentials",
		"AWS_ACCESS_KEY_ID=AKIA" + s.Pick(seed.Base32, 16),
		"AWS_SECRET_ACCESS_KEY=" + s.Pick(seed.Base64, 40),
		"AWS_DEFAULT_REGION=us-east-1",
		"AWS_ENDPOINT_URL=" + endpoint,
	}
}

// DB apunta al honeypot MySQL de esta instancia. El usuario codifica el ID del token, de modo que
// cualquier intento de conexion queda atribuido sin ambiguedad.
func DB(user, password, host string, port int) []string {
	return []string{
		"# Primary database",
		"DB_CONNECTION=mysql",
		"DB_HOST=" + host,
		fmt.Sprintf("DB_PORT=%d", port),
		"DB_DATABASE=production",
		"DB_USERNAME=" + user,
		"DB_PASSWORD=" + password,
		fmt.Sprintf("DATABASE_URL=mysql://%s:%s@%s:%d/production", user, password, host, port),
	}
}

// GitHub: token con el formato moderno y checksum CRC32 valido.
func GitHub(s *seed.Stream, endpoint string) []string {
	return []string{
		"# GitHub",
		"GITHUB_TOKEN=" + s.GitHubToken(),
		"GITHUB_API_URL=" + endpoint,
		"GITHUB_WEBHOOK_SECRET=" + s.Pick(seed.LowerHex, 40),
	}
}

func Stripe(s *seed.Stream, endpoint string) []string {
	return []string{
		"# Stripe",
		"STRIPE_SECRET_KEY=sk_live_" + s.Pick(seed.Base62, 32),
		"STRIPE_WEBHOOK_SECRET=whsec_" + s.Pick(seed.Base62, 32),
		"STRIPE_API_BASE=" + endpoint,
	}
}
