package auth

import (
	fmt "fmt"
	"net"
	"strings"

	"github.com/kubecorp/coral/config"
	auth "github.com/kubecorp/coral/sdk/go/auth"
	entity "github.com/kubecorp/coral/sdk/go/entity"
	policy "github.com/kubecorp/coral/sdk/go/policy"
	policysvc "github.com/kubecorp/coral/svc/policy"
	"github.com/ryanuber/go-glob"
	log "github.com/sirupsen/logrus"
	context "golang.org/x/net/context"
)

// Authorization manages the authorization of requests
type Authorization struct {
	Policies *policysvc.Server
}

func init() {
	c := config.GetConfig()
	if c.Debug {
		log.SetLevel(log.DebugLevel)
	}
}

// Allowed checks if an entity is allowed to access a resource
// TODO: precompile
func (a *Authorization) Allowed(ctx context.Context, e *entity.Entity, req *auth.AuthorizationRequest) (bool, error) {
	log.Debug("========= Allowed ========= \n======= entity: %+v \n======= req: %+v ", e, req) // TODO: this should be audit
	pols, err := a.Policies.ListPolicies(ctx, &policy.Query{EntityAttributes: e.Attributes})
	if err != nil {
		return false, err
	}

	allowed := false
	for _, p := range pols.Policies {
		log.Debugf("---- testing policy: %+v", p)
		switch strings.ToLower(p.Effect) {
		case "allow":
			if allowed {
				continue
			}
			if !a.requestAttributesAllowed(ctx, req, p.RequestAttributes) {
				log.Debug("request attr not allowed")
				continue
			}
			if req.Http != nil {
				allowed = a.httpAllowed(ctx, req, p)
				log.Debug("http allowed: ", allowed)
				if allowed {
					continue
				}
			}
			if req.Grpc != nil {
				allowed = a.grpcAllowed(ctx, req, p)
				log.Debug("grpc allowed: ", allowed)
				if allowed {
					continue
				}
			}
		case "deny":
			log.Debug("checking deny")
			if !a.requestAttributesAllowed(ctx, req, p.RequestAttributes) {
				continue
			}
			if req.Http != nil {
				allowed = a.httpAllowed(ctx, req, p)
				log.Debug("http allowed: ", allowed)
				if allowed {
					allowed = false
					break
				}
			}
			if req.Grpc != nil {
				allowed = a.grpcAllowed(ctx, req, p)
				log.Debug("grpc allowed: ", allowed)
				if allowed {
					allowed = false
					break
				}
			}
		default:
			return false, fmt.Errorf("policy effect unknown")
		}
	}
	return allowed, nil
}

// httpAllowed test whether a given policy allows the http action in the request if specified
func (a *Authorization) httpAllowed(ctx context.Context, req *auth.AuthorizationRequest, p *policy.Policy) bool {
	allowed := false
	if len(p.Http) == 0 {
		log.Debug("no http policies")
		return false
	}
	httpAllowed := false
	for _, hpol := range p.Http {
		if !contains(hpol.Actions, req.Http.Action) {
			log.Debug("actions not equal")
			continue
		}
		fmt.Printf("policy path: %+v req path: %v \n", hpol.Path, req.Http.Path)
		if !glob.Glob(hpol.Path, req.Http.Path) {
			log.Debug("paths don't match")
			continue
		}
		if !a.requestAttributesAllowed(ctx, req, hpol.RequestAttributes) {
			log.Debug("attr not allowed")
			continue
		}
		queryAllowed := true
		for k, v := range hpol.Query {
			log.Debugf("testing %v key and %v value in query", k, v)
			queryAllowed := false
			if len(req.Http.Query) == 0 && k == "*" {
				continue
			}
			for key, value := range req.Http.Query {
				if !glob.Glob(k, key) {
					log.Debugf("key %v does not match %v", k, key)
					continue
				}
				if !glob.Glob(v, value) {
					log.Debugf("value %v does not match %v", v, value)
					continue
				}
				queryAllowed = true
			}
			if !queryAllowed {
				log.Debug("query not allowed")
				break
			}
		}
		log.Debug("query allowed: ", queryAllowed)
		if queryAllowed {
			httpAllowed = true
			break
		}
	}
	if httpAllowed {
		allowed = true
	}
	log.Debug("returning http allowed: ", httpAllowed)
	return allowed
}

// grpcAllowed test whether a given policy allows the grpc method in the request if specified
func (a *Authorization) grpcAllowed(ctx context.Context, req *auth.AuthorizationRequest, p *policy.Policy) bool {
	allowed := false
	if len(p.Grpc) == 0 {
		log.Debug("no grpc policies")
		return false
	}
	grpcAllowed := false
	for _, gpol := range p.Grpc {
		if !contains(gpol.Methods, req.Grpc.Method) {
			log.Debug("method not allowed")
			continue
		}
		if !glob.Glob(gpol.Service, req.Grpc.Service) {
			log.Debug("service not allowed")
			continue
		}
		if !a.requestAttributesAllowed(ctx, req, gpol.RequestAttributes) {
			log.Debug("request attributes not allowed")
			continue
		}
		parametersAllowed := true
		for k, v := range gpol.Parameters {
			paramAllowed := false
			if len(req.Grpc.Parameters) == 0 && k == "*" {
				continue
			}
			for key, value := range req.Grpc.Parameters {
				if !glob.Glob(k, key) {
					log.Debugf("key %v does not match %v", k, key)
					continue
				}
				if !glob.Glob(v, value) {
					log.Debugf("value %v does not match %v", v, value)
					continue
				}
				paramAllowed = true
			}
			if !paramAllowed {
				log.Debug("param not allowed")
				break
			}
		}
		log.Debug("parameters allowed: ", parametersAllowed)
		if parametersAllowed {
			grpcAllowed = true
			break
		}
	}
	if grpcAllowed {
		allowed = true
	}
	log.Debug("returning grpc allowed: ", allowed)
	return allowed
}

// requestAttributesAllowed iterates through HTTP paths in policies and matches
func (a *Authorization) requestAttributesAllowed(ctx context.Context, req *auth.AuthorizationRequest, ra *policy.RequestAttributes) bool {
	if ra == nil {
		log.Debug("request attributes don't exists, returning true")
		return true
	}
	for k, v := range ra.Headers {
		headerAllowed := false
		for key, value := range req.Headers {
			if !glob.Glob(k, key) {
				log.Debugf("key %v does not match %v", k, key)
				continue
			}
			valueMatch := false
			for _, vv := range value.Values {
				if glob.Glob(v, vv) {
					valueMatch = true
				}
			}
			if !valueMatch {
				log.Debug("values don't match")
				continue
			}
			headerAllowed = true
		}
		if !headerAllowed {
			fmt.Println("header not allowed")
			return false
		}
	}
	if ra.Host != "" {
		if !glob.Glob(ra.Host, req.Host) {
			log.Debugf("host doesn't match: ra host: %v req host: %v", ra.Host, req.Host)
			return false
		}
	}
	if ra.Cidr != "" {
		_, ipnet, err := net.ParseCIDR(ra.Cidr)
		if err != nil {
			log.Debug("cidr doesn't match")
			return false
		}
		ip := net.ParseIP(req.RemoteAddr)
		if !ipnet.Contains(ip) {
			log.Debug("cidr doesn't match: ra cidr: %v remote addr: %v", ra.Cidr, req.RemoteAddr)
			return false
		}
	}

	return true
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if glob.Glob(a, e) {
			return true
		}
	}
	return false
}
