package pasetotoken

import (
	"fmt"
	"time"

	"github.com/vk-rv/pvx"
)

// PasetoLocalMaker is a PASETO token maker
type PasetoPublicMaker struct {
	paseto *pvx.ProtoV4Public
	pair   PasetoKeyPair
}

// NewPasetoPublicMaker creates a new PasetoPublicMaker
func NewPasetoPublicMaker(pair PasetoKeyPair) Maker {
	pv4 := pvx.NewPV4Public()

	maker := &PasetoPublicMaker{
		paseto: pv4,
		pair:   pair,
	}

	return maker
}

// CreateToken creates a new token for a specific username and duration
func (maker *PasetoPublicMaker) CreateToken(userID string, duration time.Duration) (string, error) {

	sk := maker.pair.GetSecretKey()
	if sk == nil {
		return "", fmt.Errorf("can't create token with no secret key")
	}

	payload, err := NewPayload(userID, duration)
	if err != nil {
		return "", err
	}

	token, err := maker.paseto.Sign(sk, payload)
	if err != nil {
		return "", err
	}

	return token, nil
}

// VerifyToken checks if the token is valid or not
func (maker *PasetoPublicMaker) VerifyToken(token string) (*Payload, error) {

	pk := maker.pair.GetPublicKey()
	if pk == nil {
		return nil, fmt.Errorf("can't create token with no public key")
	}

	tk := maker.paseto.Verify(token, pk)
	if tk.Err() != nil {
		return nil, ErrInvalidToken
	}

	payload := &Payload{}
	if err := tk.ScanClaims(payload); err != nil {
		return nil, ErrInvalidToken
	}

	err := payload.Valid()
	if err != nil {
		return nil, err
	}

	return payload, nil
}
