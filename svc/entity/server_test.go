package entity_test

import (
	"fmt"
	"log"
	"os"
	"testing"

	context "golang.org/x/net/context"

	"github.com/go-pg/pg"
	"github.com/kubecorp/coral/integration"
	"github.com/kubecorp/coral/sdk/go/entity"
	. "github.com/kubecorp/coral/svc/entity"
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

	// integration.KillAll()
	os.Exit(0)
}

func TestEntity(t *testing.T) {
	c := context.Background()
	fmt.Println("creating entity...")
	ent := &entity.Entity{
		Attributes: map[string]string{
			"team":  "myteam",
			"email": "mavle@gmail.com",
		},
		Authentication: &entity.EntityAuth{
			Jwt: []*entity.JWTAuth{
				&entity.JWTAuth{
					Name: "google",
					Claims: map[string]string{
						"sub": "mavle",
					},
				},
			},
			Basic: []*entity.BasicAuth{
				&entity.BasicAuth{
					Id:     "myid",
					Secret: "mysecret",
				},
			},
		},
		Billing: []*entity.EntityBilling{
			&entity.EntityBilling{
				Account: "mystripe",
			},
		},
	}
	e, err := s.CreateEntity(c, ent)
	assert.Nil(t, err)
	assert.NotNil(t, e)
	fmt.Println("entity created: ", e)

	ent1 := &entity.Entity{
		Attributes: map[string]string{
			"team":  "mynewteam",
			"email": "mavle@gmail.com",
		},
		Authentication: &entity.EntityAuth{
			Jwt: []*entity.JWTAuth{
				&entity.JWTAuth{
					Name: "google",
					Claims: map[string]string{
						"sub": "mavle",
					},
				},
			},
			Basic: []*entity.BasicAuth{
				&entity.BasicAuth{
					Id:     "myid1",
					Secret: "mysecret1",
				},
			},
		},
		Billing: []*entity.EntityBilling{
			&entity.EntityBilling{
				Account: "mystripe",
			},
		},
	}
	e1, err := s.CreateEntity(c, ent1)
	assert.Nil(t, err)
	assert.NotNil(t, e)
	fmt.Println("entity created: ", e1)

	fmt.Println("getting entity by key")
	entK, err := s.GetEntity(c, &entity.IDQuery{KeyId: "myid1"})
	assert.Nil(t, err)
	assert.NotNil(t, entK)
	fmt.Println("got entity by key: ", entK)

	fmt.Println("getting entity by claims")
	cq := &entity.JWTAuth{Name: "google", Claims: map[string]string{"sub": "mavle"}}
	entC, err := s.GetEntity(c, &entity.IDQuery{Claims: cq})
	assert.Nil(t, err)
	assert.NotNil(t, entC)
	fmt.Println("got entity by claims: ", entC)

	fmt.Println("listing entities...")
	ents, err := s.ListEntities(c, &entity.Query{})
	assert.Nil(t, err)
	fmt.Println("entity list: ", ents)

	fmt.Println("updating entity...")
	entU := &entity.Entity{
		Id: e.Id,
		Attributes: map[string]string{
			"team":  "myupdatedtean",
			"email": "mavle@gmail.com",
		},
		Authentication: &entity.EntityAuth{
			Jwt: []*entity.JWTAuth{
				&entity.JWTAuth{
					Name: "google",
					Claims: map[string]string{
						"subject": "mavlenew",
					},
				},
			},
			Basic: []*entity.BasicAuth{
				&entity.BasicAuth{
					Id:     "myidnew",
					Secret: "mysecretnew",
				},
			},
		},
		Billing: []*entity.EntityBilling{
			&entity.EntityBilling{
				Account: "mystripe",
			},
		},
	}
	eU, err := s.UpdateEntity(c, entU)
	assert.Nil(t, err)
	assert.Equal(t, eU.Attributes, entU.Attributes)
	fmt.Println("updated entity: ", eU)

	fmt.Println("patching entity...")
	entP := &entity.Entity{
		Id: e.Id,
		Attributes: map[string]string{
			"team": "mypatchedtean",
		},
	}
	eP, err := s.PatchEntity(c, entP)
	assert.Nil(t, err)
	assert.Equal(t, entP.Attributes, eP.Attributes)
	fmt.Println("patched entity: ", eP)

	fmt.Println("deleting entity...")
	_, err = s.DeleteEntity(c, &entity.IDQuery{Id: e.Id})
	assert.Nil(t, err)

	_, err = s.GetEntity(c, &entity.IDQuery{Id: e.Id})
	assert.NotNil(t, err)
}
