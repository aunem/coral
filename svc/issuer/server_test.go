package issuer_test

import (
	"fmt"
	"log"
	"os"
	"testing"

	context "golang.org/x/net/context"

	"github.com/go-pg/pg"
	"github.com/kubecorp/coral/integration"
	"github.com/kubecorp/coral/sdk/go/issuer"
	. "github.com/kubecorp/coral/svc/issuer"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
)

var db *pg.DB
var s *Server

func TestMain(m *testing.M) {
	var err error
	fmt.Println("creating db...")
	var db = integration.ConnectToPostgres()
	defer db.Close()

	fmt.Println("starting tests...")
	s = &Server{
		DB: db,
	}
	fmt.Println("migrating schemas...")
	err = s.Migrate()
	if err != nil {
		log.Fatal(err)
	}
	m.Run()

	integration.KillAll()
	os.Exit(0)
}

func TestIssuer(t *testing.T) {
	c := context.Background()
	fmt.Println("creating issuer...")
	iss := &issuer.Issuer{
		Name:    "myissuer",
		Issuer:  "my.host.com",
		JwksUri: "my.host.com/jwks.json",
	}
	i, err := s.CreateIssuer(c, iss)
	assert.Nil(t, err)
	assert.NotNil(t, i)
	fmt.Println("issuer created: ", i)

	iss1 := &issuer.Issuer{
		Name:    "myissuer1",
		Issuer:  "my.host1.com",
		JwksUri: "my.host1.com/jwks.json",
	}
	i1, err := s.CreateIssuer(c, iss1)
	assert.Nil(t, err)
	assert.NotNil(t, i1)
	fmt.Println("second issuer created: ", i)

	fmt.Println("listing issuers...")
	isses, err := s.ListIssuers(c, &issuer.Query{})
	assert.Nil(t, err)
	fmt.Println("issuer list: ", isses)

	fmt.Println("updating issuer...")
	issU := &issuer.Issuer{
		Id:     i.Id,
		Name:   "myissuerNew",
		Issuer: "my.host.com.new",
	}
	iU, err := s.UpdateIssuer(c, issU)
	assert.Nil(t, err)
	assert.Equal(t, iU.Name, issU.Name)
	fmt.Println("updated issuer: ", iU)

	fmt.Println("patching issuer...")
	issP := &issuer.Issuer{
		Id:   i.Id,
		Name: "myissuerPatch",
	}
	iP, err := s.PatchIssuer(c, issP)
	assert.Nil(t, err)
	assert.Equal(t, issP.Name, iP.Name)
	fmt.Println("patched issuer: ", iP)

	fmt.Println("deleting issuer...")
	_, err = s.DeleteIssuer(c, &issuer.IDQuery{Id: i.Id})
	assert.Nil(t, err)

	_, err = s.GetIssuer(c, &issuer.IDQuery{Id: i.Id})
	assert.NotNil(t, err)
}
