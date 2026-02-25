package dto

type LoginResponseDto struct {
	Token     string `json:"token"`
	ExpiresIn int64  `json:"expires_in"`
}

func NewLoginResponseDto(token string, expiresInSeconds int64) LoginResponseDto {
	return LoginResponseDto{
		Token:     token,
		ExpiresIn: expiresInSeconds,
	}
}
