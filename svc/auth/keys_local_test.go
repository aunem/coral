package auth_test

import (
	"fmt"
	"testing"
	"time"

	entity "github.com/aunem/coral/sdk/go/entity"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
	context "golang.org/x/net/context"
)

func TestJWKs(t *testing.T) {
	l := KeyManagerT.LocalKeys
	fmt.Println("creating keys...")
	err := l.CreateKeys(3)
	require.Nil(t, err)
	fmt.Println("getting public keys...")
	k, err := l.GetPublic()
	require.Nil(t, err)
	require.Equal(t, len(k), 3)
	// fmt.Println("keys: ", k)
	fmt.Println("rotating keys...")
	err = l.RotateKeys()
	require.Nil(t, err)
	fmt.Println("updating cache...")
	k, err = l.GetPublic()
	require.Nil(t, err)
	require.Equal(t, len(k), 3)
	// fmt.Println("rotated keys: ", k)
	err = l.UpdateCache()
	require.Nil(t, err)
	require.Equal(t, len(l.PrivateJWKs), 3)
	// fmt.Println("cache: ", l.JWKs)

	e := entity.Entity{
		Id:          "myid",
		CreatedTime: time.Now().Unix(),
		UpdateTime:  time.Now().Unix(),
		Attributes: map[string]string{
			"team": "myteam",
			"role": "myrole",
		},
		Authentication: &entity.EntityAuth{
			Basic: []*entity.BasicAuth{
				&entity.BasicAuth{
					Id:     "myid",
					Secret: "mysecret",
				},
			},
		},
	}
	signed, err := l.SignEntity(&e)
	require.Nil(t, err)
	fmt.Println("signed entity: ", signed)
	verified, token, err := l.VerifySignature(context.Background(), signed)
	require.Nil(t, err)
	fmt.Println("verified: ", verified)
	fmt.Println("token: ", token)
}
