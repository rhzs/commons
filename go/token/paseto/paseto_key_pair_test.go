package pasetotoken

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPasetoKeyPair(t *testing.T) {

	pkp := createPasetoTokenWithED25519()

	require.NotEmpty(t, pkp.GetPublicKey())
	require.NotEmpty(t, pkp.GetSecretKey())
}
