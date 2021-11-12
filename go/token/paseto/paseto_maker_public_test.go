package pasetotoken

import (
	"testing"
	"time"

	util "github.com/rhzs/commons/util/random"
	"github.com/stretchr/testify/require"
)

func TestPasetoPublicToken(t *testing.T) {

	pkp := createPasetoTokenWithED25519()

	maker := NewPasetoPublicMaker(pkp)

	username := util.RandomOwner()
	duration := time.Minute

	token, err := maker.CreateToken(username, duration)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	payload, err := maker.VerifyToken(token)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotZero(t, payload.ID)
	require.Equal(t, username, payload.UserID)

	issuedAt := time.Now()
	expiredAt := issuedAt.Add(duration)

	require.WithinDuration(t, issuedAt, payload.IssuedAt, time.Second)
	require.WithinDuration(t, expiredAt, payload.ExpiredAt, time.Second)
}
