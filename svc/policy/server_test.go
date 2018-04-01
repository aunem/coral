package policy_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	context "golang.org/x/net/context"

	"github.com/aunem/coral/integration"
	"github.com/aunem/coral/sdk/go/policy"
	. "github.com/aunem/coral/svc/policy"
	"github.com/go-pg/pg"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
)

var db *pg.DB
var s *Server

func TestMain(m *testing.M) {
	var err error
	fmt.Println("creating db...")
	var db = integration.ConnectToPostgres()
	defer db.Close()
	db.OnQueryProcessed(func(event *pg.QueryProcessedEvent) {
		query, err := event.FormattedQuery()
		if err != nil {
			panic(err)
		}

		log.Debugf("SQL QUERY: %s %s", time.Since(event.StartTime), query)
	})
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
	ctx := context.Background()
	fmt.Println("creating policy...")
	pol := &policy.Policy{
		Name: "mypol",
		EntityAttributes: map[string]string{
			"team": "myteam",
		},
		Effect: "allow",
		RequestAttributes: &policy.RequestAttributes{
			Headers: map[string]string{
				"MYHEADER": "*",
			},
			Cidr: "0.0.0.0/0",
			Host: "my.host.*",
		},
		Http: []*policy.RoutePolicy{
			&policy.RoutePolicy{
				Path:    "/mypath",
				Actions: []string{"*"},
			},
		},
	}
	p, err := s.CreatePolicy(ctx, pol)
	require.Nil(t, err)
	require.NotNil(t, p)
	fmt.Printf("policy created: %+v \n", p)

	pol1 := &policy.Policy{
		Name: "mypol1",
		EntityAttributes: map[string]string{
			"team":  "myteam1",
			"group": "firstgroup",
		},
		Effect: "allow",
		RequestAttributes: &policy.RequestAttributes{
			Headers: map[string]string{
				"MYHEADER": "*",
			},
			Cidr: "0.0.0.0/0",
			Host: "my.host.*",
		},
		Http: []*policy.RoutePolicy{
			&policy.RoutePolicy{
				Path:    "/myroute",
				Actions: []string{"POST"},
				RequestAttributes: &policy.RequestAttributes{
					Headers: map[string]string{
						"HEADER": "HEADER*",
					},
				},
			},
		},
	}
	p1, err := s.CreatePolicy(ctx, pol1)
	require.Nil(t, err)
	require.NotNil(t, p1)
	fmt.Printf("second policy created: %+v \n", p1)

	fmt.Println("listing policies...")
	policies, err := s.ListPolicies(ctx, &policy.Query{EntityAttributes: map[string]string{"team": "myteam1"}})
	require.Nil(t, err)
	require.Len(t, policies.Policies, 1)
	fmt.Println("policy list: ", policies)

	policies, err = s.ListPolicies(ctx, &policy.Query{EntityAttributes: map[string]string{"group": "firstgroup"}})
	require.Nil(t, err)
	require.Len(t, policies.Policies, 1)
	fmt.Println("policy list: ", policies)

	fmt.Println("updating policy...")
	polU := &policy.Policy{
		Id:   p1.Id,
		Name: "newpolname",
	}
	pU, err := s.UpdatePolicy(ctx, polU)
	require.Nil(t, err)
	require.Equal(t, polU.Name, pU.Name)
	fmt.Printf("updated policy: %+v \n", pU)

	fmt.Println("patching policy...")
	polP := &policy.Policy{
		Id:   p.Id,
		Name: "newname",
	}
	pP, err := s.PatchPolicy(ctx, polP)
	require.Nil(t, err)
	require.Equal(t, polP.Name, pP.Name)
	fmt.Println("patched policy: ", pP)

	fmt.Println("deleting policy..")
	_, err = s.DeletePolicy(ctx, &policy.IDQuery{Id: p.Id})
	require.Nil(t, err)

	_, err = s.GetPolicy(ctx, &policy.IDQuery{Id: p.Id})
	require.NotNil(t, err)
}
