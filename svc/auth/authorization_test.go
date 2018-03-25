package auth_test

import (
	"fmt"
	"testing"

	auth "github.com/kubecorp/coral/sdk/go/auth"
	entity "github.com/kubecorp/coral/sdk/go/entity"
	"github.com/kubecorp/coral/sdk/go/policy"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	context "golang.org/x/net/context"
)

func TestAuthorizationAllowAll(t *testing.T) {
	ctx := context.Background()
	p0 := &policy.Policy{
		Name: "mypol",
		EntityAttributes: map[string]string{
			"team": "myteam",
			"role": "myrole",
		},
		Effect: "allow",
		Http: []*policy.RoutePolicy{
			&policy.RoutePolicy{
				Path:    "*",
				Actions: []string{"*"},
				Query: map[string]string{
					"*": "*",
				},
			},
		},
		Grpc: []*policy.MethodPolicy{
			&policy.MethodPolicy{
				Service: "*",
				Methods: []string{"*"},
				Parameters: map[string]string{
					"*": "*",
				},
			},
		},
	}
	fmt.Println("creating policy p0")
	p0c, err := AuthorizationManager.Policies.CreatePolicy(ctx, p0)
	fmt.Println("poc, err: ", p0c, err)
	assert.Nil(t, err)
	fmt.Println("starting tests...")
	alwdtests := []struct {
		ent     *entity.Entity
		req     *auth.AuthorizationRequest
		allowed bool
	}{
		{ent: &entity.Entity{
			Attributes: map[string]string{
				"team": "myteam",
			},
			Authentication: &entity.EntityAuth{
				Basic: []*entity.BasicAuth{
					&entity.BasicAuth{
						Id:     "myid",
						Secret: "mysecret",
					},
				},
			},
		}, req: &auth.AuthorizationRequest{
			Host: "my.host.com",
			Headers: map[string]*auth.HeaderVals{
				"MY": &auth.HeaderVals{[]string{"VAL"}},
			},
			Http: &auth.HTTPRequest{
				Path:   "/my/path",
				Action: "GET",
			},
		}, allowed: true},
		{ent: &entity.Entity{
			Attributes: map[string]string{
				"team": "myteam1",
			},
			Authentication: &entity.EntityAuth{
				Basic: []*entity.BasicAuth{
					&entity.BasicAuth{
						Id:     "myid",
						Secret: "mysecret",
					},
				},
			},
		}, req: &auth.AuthorizationRequest{
			Host: "my.host.com",
			Headers: map[string]*auth.HeaderVals{
				"MY": &auth.HeaderVals{[]string{"VAL"}},
			},
			Http: &auth.HTTPRequest{
				Path:   "/my/path",
				Action: "GET",
			},
		}, allowed: false},
		{ent: &entity.Entity{
			Attributes: map[string]string{
				"team": "myteam",
			},
			Authentication: &entity.EntityAuth{
				Basic: []*entity.BasicAuth{
					&entity.BasicAuth{
						Id:     "myid",
						Secret: "mysecret",
					},
				},
			},
		}, req: &auth.AuthorizationRequest{
			Host: "my.host.com",
			Headers: map[string]*auth.HeaderVals{
				"MY": &auth.HeaderVals{[]string{"VAL"}},
			},
			Grpc: &auth.GRPCRequest{
				Service: "myservice",
				Method:  "mymethod",
				Parameters: map[string]string{
					"my": "param",
				},
			},
		}, allowed: true},
	}
	for _, tt := range alwdtests {
		fmt.Printf("\n\n----- testing: \nent: %v \nreq: %v \nallowed: %v \n\n", tt.ent, tt.req, tt.allowed)
		alwd, err := AuthorizationManager.Allowed(ctx, tt.ent, tt.req)
		fmt.Printf("result: alwd: %v err: %v \n", alwd, err)
		assert.Nil(t, err)
		if alwd != tt.allowed {
			t.Errorf("ent: %v \n req: %v \n => %v, want %v", tt.ent, tt.req, alwd, tt.allowed)
		}
	}
	_, err = AuthorizationManager.Policies.DeletePolicy(ctx, &policy.IDQuery{Id: p0c.Id})
	assert.Nil(t, err)
}

func TestAuthorizationDeny(t *testing.T) {
	ctx := context.Background()
	p0 := &policy.Policy{
		Name: "mypol",
		EntityAttributes: map[string]string{
			"team": "myteam",
			"role": "myrole",
		},
		Effect: "allow",
		Http: []*policy.RoutePolicy{
			&policy.RoutePolicy{
				Path:    "*",
				Actions: []string{"*"},
				Query: map[string]string{
					"*": "*",
				},
			},
		},
		Grpc: []*policy.MethodPolicy{
			&policy.MethodPolicy{
				Service: "*",
				Methods: []string{"*"},
				Parameters: map[string]string{
					"*": "*",
				},
			},
		},
	}
	p0c, err := AuthorizationManager.Policies.CreatePolicy(ctx, p0)
	p1 := &policy.Policy{
		Name: "mypol",
		EntityAttributes: map[string]string{
			"team": "myteam",
		},
		Effect: "deny",
		Http: []*policy.RoutePolicy{
			&policy.RoutePolicy{
				Path:    "*",
				Actions: []string{"*"},
				Query: map[string]string{
					"*": "*",
				},
			},
		},
		Grpc: []*policy.MethodPolicy{
			&policy.MethodPolicy{
				Service: "*",
				Methods: []string{"*"},
				Parameters: map[string]string{
					"*": "*",
				},
			},
		},
	}
	p1c, err := AuthorizationManager.Policies.CreatePolicy(ctx, p1)
	assert.Nil(t, err)
	alwdtests := []struct {
		ent     *entity.Entity
		req     *auth.AuthorizationRequest
		allowed bool
	}{
		{&entity.Entity{
			Attributes: map[string]string{
				"team": "myteam",
			},
			Authentication: &entity.EntityAuth{
				Basic: []*entity.BasicAuth{
					&entity.BasicAuth{
						Id:     "myid",
						Secret: "mysecret",
					},
				},
			},
		}, &auth.AuthorizationRequest{
			Host: "my.host.com",
			Headers: map[string]*auth.HeaderVals{
				"MY": &auth.HeaderVals{[]string{"VAL"}},
			},
			Http: &auth.HTTPRequest{
				Path:   "/my/path",
				Action: "GET",
			},
		}, false},
		{&entity.Entity{
			Attributes: map[string]string{
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
		}, &auth.AuthorizationRequest{
			Host: "my.host.com",
			Headers: map[string]*auth.HeaderVals{
				"MY": &auth.HeaderVals{[]string{"VAL"}},
			},
			Http: &auth.HTTPRequest{
				Path:   "/my/path",
				Action: "GET",
			},
		}, true},
	}
	for _, tt := range alwdtests {
		fmt.Printf("\n\n----- testing: \nent: %v \nreq: %v \nallowed: %v \n\n", tt.ent, tt.req, tt.allowed)
		alwd, err := AuthorizationManager.Allowed(ctx, tt.ent, tt.req)
		fmt.Printf("result: alwd: %v err: %v \n", alwd, err)
		assert.Nil(t, err)
		if alwd != tt.allowed {
			t.Errorf("ent: %v \n req: %v \n => %v, want %v", tt.ent, tt.req, alwd, tt.allowed)
		}
	}
	_, err = AuthorizationManager.Policies.DeletePolicy(ctx, &policy.IDQuery{Id: p0c.Id})
	assert.Nil(t, err)
	_, err = AuthorizationManager.Policies.DeletePolicy(ctx, &policy.IDQuery{Id: p1c.Id})
	assert.Nil(t, err)
}

func TestAuthorizationProtocol(t *testing.T) {
	ctx := context.Background()
	p0 := &policy.Policy{
		Name: "mypol",
		EntityAttributes: map[string]string{
			"team": "myteam",
			"role": "myrole",
		},
		Effect: "allow",
		Http: []*policy.RoutePolicy{
			&policy.RoutePolicy{
				Path:    "/my/*",
				Actions: []string{"GET", "POST"},
				Query: map[string]string{
					"myquery": "*",
				},
			},
		},
		Grpc: []*policy.MethodPolicy{
			&policy.MethodPolicy{
				Service: "my*",
				Methods: []string{"my*"},
				Parameters: map[string]string{
					"myparam": "test",
				},
			},
		},
	}
	p0c, err := AuthorizationManager.Policies.CreatePolicy(ctx, p0)
	assert.Nil(t, err)
	alwdtests := []struct {
		ent     *entity.Entity
		req     *auth.AuthorizationRequest
		allowed bool
	}{
		{&entity.Entity{
			Attributes: map[string]string{
				"team": "myteam",
			},
			Authentication: &entity.EntityAuth{
				Basic: []*entity.BasicAuth{
					&entity.BasicAuth{
						Id:     "myid",
						Secret: "mysecret",
					},
				},
			},
		}, &auth.AuthorizationRequest{
			Http: &auth.HTTPRequest{
				Path:   "/my/path",
				Action: "GET",
				Query: map[string]string{
					"myquery": "1",
				},
			},
		}, true},
		{&entity.Entity{
			Attributes: map[string]string{
				"team": "myteam",
			},
			Authentication: &entity.EntityAuth{
				Basic: []*entity.BasicAuth{
					&entity.BasicAuth{
						Id:     "myid",
						Secret: "mysecret",
					},
				},
			},
		}, &auth.AuthorizationRequest{
			Http: &auth.HTTPRequest{
				Path:   "/my/path",
				Action: "PATCH",
			},
		}, false},
		{&entity.Entity{
			Attributes: map[string]string{
				"team": "myteam",
			},
			Authentication: &entity.EntityAuth{
				Basic: []*entity.BasicAuth{
					&entity.BasicAuth{
						Id:     "myid",
						Secret: "mysecret",
					},
				},
			},
		}, &auth.AuthorizationRequest{
			Http: &auth.HTTPRequest{
				Path:   "/my1/path",
				Action: "GET",
			},
		}, false},
		{&entity.Entity{
			Attributes: map[string]string{
				"team": "myteam",
			},
			Authentication: &entity.EntityAuth{
				Basic: []*entity.BasicAuth{
					&entity.BasicAuth{
						Id:     "myid",
						Secret: "mysecret",
					},
				},
			},
		}, &auth.AuthorizationRequest{
			Grpc: &auth.GRPCRequest{
				Service: "myService",
				Method:  "myMethod",
				Parameters: map[string]string{
					"my": "param",
				},
			},
			Http: &auth.HTTPRequest{
				Path:   "/my/path",
				Action: "GET",
				Query: map[string]string{
					"myquery": "1",
				},
			},
		}, true},
		{&entity.Entity{
			Attributes: map[string]string{
				"team": "myteam",
			},
			Authentication: &entity.EntityAuth{
				Basic: []*entity.BasicAuth{
					&entity.BasicAuth{
						Id:     "myid",
						Secret: "mysecret",
					},
				},
			},
		}, &auth.AuthorizationRequest{
			Grpc: &auth.GRPCRequest{
				Service: "myService",
				Method:  "newMethod",
			},
		}, false},
	}
	for _, tt := range alwdtests {
		fmt.Printf("\n\n----- testing: \nent: %v \nreq: %v \nallowed: %v \n\n", tt.ent, tt.req, tt.allowed)
		alwd, err := AuthorizationManager.Allowed(ctx, tt.ent, tt.req)
		fmt.Printf("result: alwd: %v err: %v \n", alwd, err)
		assert.Nil(t, err)
		if alwd != tt.allowed {
			fmt.Println("!!! not eq")
			t.Errorf("ent: %v \n req: %v \n => %v, want %v", tt.ent, tt.req, alwd, tt.allowed)
		}
	}
	_, err = AuthorizationManager.Policies.DeletePolicy(ctx, &policy.IDQuery{Id: p0c.Id})
	assert.Nil(t, err)
}

func TestAuthorizationReqeustAttributes(t *testing.T) {
	ctx := context.Background()
	p0 := &policy.Policy{
		Name: "mypol",
		EntityAttributes: map[string]string{
			"team": "myteam",
			"role": "myrole",
		},
		Effect: "allow",
		RequestAttributes: &policy.RequestAttributes{
			Headers: map[string]string{
				"MY": "HEADER",
			},
			Cidr: "10.0.0.0/24",
			Host: "my.host.com",
		},
		Http: []*policy.RoutePolicy{
			&policy.RoutePolicy{
				Path:    "*",
				Actions: []string{"*"},
				Query: map[string]string{
					"*": "*",
				},
			},
		},
		Grpc: []*policy.MethodPolicy{
			&policy.MethodPolicy{
				Service: "*",
				Methods: []string{"*"},
				Parameters: map[string]string{
					"*": "*",
				},
			},
		},
	}
	p0c, err := AuthorizationManager.Policies.CreatePolicy(ctx, p0)
	assert.Nil(t, err)
	alwdtests := []struct {
		ent     *entity.Entity
		req     *auth.AuthorizationRequest
		allowed bool
	}{
		{&entity.Entity{
			Attributes: map[string]string{
				"team": "myteam",
			},
			Authentication: &entity.EntityAuth{
				Basic: []*entity.BasicAuth{
					&entity.BasicAuth{
						Id:     "myid",
						Secret: "mysecret",
					},
				},
			},
		}, &auth.AuthorizationRequest{
			Host: "my.host.com",
			Headers: map[string]*auth.HeaderVals{
				"MY": &auth.HeaderVals{[]string{"HEADER"}},
			},
			Http: &auth.HTTPRequest{
				Path:   "/my/path",
				Action: "GET",
			},
			RemoteAddr: "10.0.0.0",
		}, true},
		{&entity.Entity{
			Attributes: map[string]string{
				"team": "myteam",
			},
			Authentication: &entity.EntityAuth{
				Basic: []*entity.BasicAuth{
					&entity.BasicAuth{
						Id:     "myid",
						Secret: "mysecret",
					},
				},
			},
		}, &auth.AuthorizationRequest{
			Host: "my.host.com",
			Headers: map[string]*auth.HeaderVals{
				"MY": &auth.HeaderVals{[]string{"HEADER"}},
			},
			Http: &auth.HTTPRequest{
				Path:   "/my/path",
				Action: "GET",
			},
			RemoteAddr: "10.0.1.0",
		}, false},
		{&entity.Entity{
			Attributes: map[string]string{
				"team": "myteam",
			},
			Authentication: &entity.EntityAuth{
				Basic: []*entity.BasicAuth{
					&entity.BasicAuth{
						Id:     "myid",
						Secret: "mysecret",
					},
				},
			},
		}, &auth.AuthorizationRequest{
			Host: "my.host.com",
			Headers: map[string]*auth.HeaderVals{
				"MY": &auth.HeaderVals{[]string{"VAL"}},
			},
			Http: &auth.HTTPRequest{
				Path:   "/my/path",
				Action: "GET",
			},
			RemoteAddr: "10.0.0.0",
		}, false},
		{&entity.Entity{
			Attributes: map[string]string{
				"team": "myteam",
			},
			Authentication: &entity.EntityAuth{
				Basic: []*entity.BasicAuth{
					&entity.BasicAuth{
						Id:     "myid",
						Secret: "mysecret",
					},
				},
			},
		}, &auth.AuthorizationRequest{
			Host: "my.host1.com",
			Headers: map[string]*auth.HeaderVals{
				"MY": &auth.HeaderVals{[]string{"HEADER"}},
			},
			Http: &auth.HTTPRequest{
				Path:   "/my/path",
				Action: "GET",
			},
			RemoteAddr: "10.0.0.0",
		}, false},
	}
	for _, tt := range alwdtests {
		fmt.Printf("\n\n----- testing: \nent: %v \nreq: %v \nallowed: %v \n\n", tt.ent, tt.req, tt.allowed)
		alwd, err := AuthorizationManager.Allowed(ctx, tt.ent, tt.req)
		fmt.Printf("result: alwd: %v err: %v \n", alwd, err)
		assert.Nil(t, err)
		if alwd != tt.allowed {
			fmt.Println("!!! not eq")
			t.Errorf("ent: %v \n req: %v \n => %v, want %v", tt.ent, tt.req, alwd, tt.allowed)
		}
	}
	_, err = AuthorizationManager.Policies.DeletePolicy(ctx, &policy.IDQuery{Id: p0c.Id})
	assert.Nil(t, err)
}
