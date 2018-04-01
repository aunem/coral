package auth_test

import (
	"fmt"
	"log"
	"os"
	"testing"

	context "golang.org/x/net/context"
	"google.golang.org/grpc/metadata"
	jose "gopkg.in/square/go-jose.v2"

	"github.com/aunem/coral/config"
	"github.com/aunem/coral/integration"
	"github.com/aunem/coral/sdk/go/auth"
	"github.com/aunem/coral/sdk/go/entity"
	"github.com/aunem/coral/sdk/go/policy"
	. "github.com/aunem/coral/svc/auth"
	entitysvc "github.com/aunem/coral/svc/entity"
	issuersvc "github.com/aunem/coral/svc/issuer"
	policysvc "github.com/aunem/coral/svc/policy"
	oidc "github.com/coreos/go-oidc"
	"github.com/go-pg/pg"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
)

var DB *pg.DB
var ServerT *Server
var AuthorizationManager *Authorization
var KeyManagerT *KeyManager
var EntityManagerT *entitysvc.Server
var IssuerManagerT *issuersvc.Server
var Config *config.ServerConfig

func TestMain(m *testing.M) {
	var err error
	fmt.Println("creating db...")
	DB = integration.ConnectToPostgres()
	defer DB.Close()

	Config = &config.ServerConfig{
		Issuer:   "my.issuer.com",
		TokenTTL: 86400,
		RootName: "root",
		RootPass: "pass",
	}
	fmt.Println("starting migrations...")
	fmt.Println("issuer migration...")
	IssuerManagerT = &issuersvc.Server{
		DB: DB,
	}
	err = IssuerManagerT.Migrate()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("policy migration...")
	policyServer, err := policysvc.NewServer(Config, DB)
	if err != nil {
		log.Fatal(err)
	}
	AuthorizationManager = &Authorization{
		Policies: policyServer,
	}
	fmt.Println("entity migration...")
	EntityManagerT, err = entitysvc.NewServer(Config, DB)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("key manager migration...")
	lcm := &LocalKeyManager{
		Config:      Config,
		PrivateJWKs: map[string]jose.JSONWebKey{},
		PublicJWKs:  map[string]jose.JSONWebKey{},
		DB:          DB,
	}
	err = lcm.Migrate()
	if err != nil {
		log.Fatal(err)
	}
	KeyManagerT = &KeyManager{
		LocalKeys: lcm,
		RemoteKeys: &RemoteKeyManager{
			JWKCache:      map[string]oidc.KeySet{},
			IssuerManager: IssuerManagerT,
		},
		EntityManager: EntityManagerT,
		IssuerManager: IssuerManagerT,
		Config:        Config,
	}
	ServerT = &Server{
		Keys:          KeyManagerT,
		Authorization: AuthorizationManager,
		Entities:      EntityManagerT,
		Config:        Config,
	}
	fmt.Println("starting tests...")
	m.Run()

	fmt.Println("killing containers...")
	// integration.KillAll()
	os.Exit(0)
}

func TestAuthorize(t *testing.T) {
	ctx := context.Background()
	fmt.Println("creating keys...")
	err := ServerT.Keys.LocalKeys.CreateKeys(3)
	require.Nil(t, err)

	fmt.Println("creating entity...")
	e := entity.Entity{
		Attributes: map[string]string{
			"team": "myteam",
			"role": "admin",
		},
		Authentication: &entity.EntityAuth{
			Basic: []*entity.BasicAuth{
				&entity.BasicAuth{
					Id:     "myid",
					Secret: "mysecret",
					Tags:   []string{"mytag"},
				},
			},
		},
	}
	e0, err := ServerT.Entities.CreateEntity(ctx, &e)
	require.Nil(t, err)
	require.NotNil(t, e0)

	fmt.Println("creating policy...")
	p := policy.Policy{
		Name: "mypol",
		EntityAttributes: map[string]string{
			"team": "myteam",
		},
		Effect: "allow",
		RequestAttributes: &policy.RequestAttributes{
			Host: "my.host.com",
		},
		Http: []*policy.RoutePolicy{
			&policy.RoutePolicy{
				Path:    "/my/*",
				Actions: []string{"POST"},
				Query:   map[string]string{"*": "*"},
			},
		},
		Grpc: []*policy.MethodPolicy{
			&policy.MethodPolicy{
				Service:    "myservice",
				Methods:    []string{"create"},
				Parameters: map[string]string{"*": "*"},
			},
		},
	}
	p0, err := ServerT.Authorization.Policies.CreatePolicy(ctx, &p)
	require.Nil(t, err)
	require.NotNil(t, p0)

	fmt.Println("grabbing root token...")
	md := metadata.Pairs("Authorization", fmt.Sprintf("basic %s", BasicToEnc(Config.RootName, Config.RootPass)))
	c := metadata.NewIncomingContext(context.Background(), md)
	resp, err := ServerT.SignBasic(c, &auth.Empty{})
	require.Nil(t, err)
	require.NotNil(t, resp)
	rootToken := resp.Jwt
	fmt.Printf("root signing response: %+v \n", resp)

	fmt.Println("grabbing test entity token....")
	md = metadata.Pairs("Authorization", fmt.Sprintf("basic %s", BasicToEnc("myid", "mysecret")))
	c = metadata.NewIncomingContext(context.Background(), md)
	resp, err = ServerT.SignBasic(c, &auth.Empty{})
	require.Nil(t, err)
	require.NotNil(t, resp)
	testToken := resp.Jwt
	fmt.Printf("test signing response: %+v \n", resp)

	fmt.Println("checking allowed...")
	md = metadata.Pairs("Authorization", fmt.Sprintf("bearer %s", rootToken))
	c = metadata.NewIncomingContext(context.Background(), md)
	a := auth.AuthorizationRequest{
		Http: &auth.HTTPRequest{
			Path:   "/my/path",
			Action: "POST",
			Query:  map[string]string{"my": "query"},
		},
		Host: "my.host.com",
		Headers: map[string]*auth.HeaderVals{
			"Authorization": &auth.HeaderVals{
				Values: []string{fmt.Sprintf("bearer %s", testToken)},
			},
		},
	}
	aresp, err := ServerT.Authorize(c, &a)
	require.Nil(t, err)
	require.NotNil(t, aresp)
	require.Equal(t, true, aresp.Allowed)
	require.Equal(t, e0.Id, aresp.Entity.Id)
	fmt.Printf("authorize response: %+v \n", aresp)

	fmt.Println("testing authorize and sign")
	sresp, err := ServerT.AuthorizeAndSign(c, &a)
	require.Nil(t, err)
	require.NotNil(t, sresp)
	require.Equal(t, true, sresp.Allowed)
	require.NotEmpty(t, sresp.Jwt)
	fmt.Printf("authorize and sign response: %+v \n", sresp)

	// fmt.Println("test sign only")  // TODO: test the remote pieces
	// soresp, err := ServerT.Sign(ctx, auth.SigningRequest{})
}
