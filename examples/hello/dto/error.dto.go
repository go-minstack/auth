package dto

type ErrorDto struct {
	Error string `json:"error"`
}

func NewErrorDto(err error) ErrorDto {
	return ErrorDto{Error: err.Error()}
}
