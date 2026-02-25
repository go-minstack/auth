package dto

type MessageDto struct {
	Message string `json:"message"`
}

func NewMessageDto(message string) MessageDto {
	return MessageDto{Message: message}
}
