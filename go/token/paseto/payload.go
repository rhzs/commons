package pasetotoken

import (
	"errors"
	"time"

	"github.com/segmentio/ksuid"
)

// Different types of error returned by the VerifyToken function
var (
	ErrInvalidToken = errors.New("token is invalid")
	ErrExpiredToken = errors.New("token has expired")
)

// Payload contains the payload data of the token
type Payload struct {
	ID        ksuid.KSUID `json:"id"`
	UserID    string      `json:"user_id'`
	IssuedAt  time.Time   `json:"issued_at"`
	ExpiredAt time.Time   `json:"expired_at"`
}

// NewPayload creates a new token payload with a specific username and duration
func NewPayload(userID string, duration time.Duration) (*Payload, error) {
	payload := &Payload{
		ID:        ksuid.New(),
		UserID:    userID,
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().Add(duration),
	}
	return payload, nil
}

// Valid checks if the token payload is valid or not
func (payload *Payload) Valid() error {
	if time.Now().After(payload.ExpiredAt) {
		return ErrExpiredToken
	}
	return nil
}
