package policy

import (
	"context"
	"fmt"

	"github.com/gobwas/glob"
	log "github.com/sirupsen/logrus"

	"github.com/aunem/coral/config"
	"github.com/aunem/coral/sdk/go/policy"
	"github.com/go-pg/pg"
	"github.com/imdario/mergo"
	uuid "github.com/satori/go.uuid"
)

// Server is the implementation of the grpc interface for issuer.proto
type Server struct {
	DB *pg.DB
}

// NewServer creates a new server, migrates the db, and performs any necessary bootstrapping
func NewServer(c *config.ServerConfig, db *pg.DB) (*Server, error) {
	s := &Server{
		DB: db,
	}
	err := s.Migrate()
	if err != nil {
		return nil, err
	}
	var p policy.Policy
	err = s.DB.Model(&p).
		Where("name = 'root'").
		Limit(1).
		Select()
	if err == pg.ErrNoRows {
		pRoot := policy.Policy{
			Name: "root",
			EntityAttributes: map[string]string{
				"name": c.RootName,
			},
			Effect: "allow",
			Http: []*policy.RoutePolicy{
				&policy.RoutePolicy{
					Path:    "*",
					Actions: []string{"*"},
					Query:   map[string]string{"*": "*"},
				},
			},
			Grpc: []*policy.MethodPolicy{
				&policy.MethodPolicy{
					Service:    "*",
					Methods:    []string{"*"},
					Parameters: map[string]string{"*": "*"},
				},
			},
		}
		id, err := uuid.NewV4()
		if err != nil {
			return nil, err
		}
		pRoot.Id = id.String()
		err = s.DB.Insert(&pRoot)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	return s, nil
}

// Migrate runs schema migration on the DB
func (s *Server) Migrate() error {
	for _, model := range []interface{}{&policy.MethodPolicy{}, &policy.RoutePolicy{}, &policy.Policy{}} {
		err := s.DB.CreateTable(model, nil)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetPolicy gets a policy by ID
func (s *Server) GetPolicy(ctx context.Context, q *policy.IDQuery) (*policy.Policy, error) {
	if q.Id != "" {
		p := policy.Policy{Id: q.Id}
		err := s.DB.Select(&p)
		return &p, err
	} else if q.Name != "" {
		var p policy.Policy
		err := s.DB.Model(&p).
			Where("name = ?", q.Name).
			Limit(1).
			Select()
		return &p, err
	} else {
		return nil, fmt.Errorf("query is required")
	}
}

// ListPolicies lists a policies by entity attributes, leave blank to list all
func (s *Server) ListPolicies(ctx context.Context, q *policy.Query) (*policy.Policies, error) {
	var policies []policy.Policy
	if len(q.EntityAttributes) == 0 {
		err := s.DB.Model(&policies).Select()
		if err != nil {
			return nil, err
		}
	} else {
		//TODO: Need key wildcard matching
		var candidates []policy.Policy
		keys := []string{}
		for k := range q.EntityAttributes {
			keys = append(keys, k)
		}
		err := s.DB.Model(&candidates).Where(`entity_attributes \?| ?`, pg.Array(keys)).Select()
		if err != nil {
			return nil, err
		}
		log.Debugf("candidates: %+v", candidates)
		for _, pol := range candidates {
			for k, v := range q.EntityAttributes {
				if val, ok := pol.EntityAttributes[k]; ok {
					g := glob.MustCompile(val)
					if g.Match(v) {
						policies = append(policies, pol)
					}
				}
			}
		}
	}
	ppol := []*policy.Policy{}
	for _, p := range policies {
		ppol = append(ppol, &p)
	}
	return &policy.Policies{Policies: ppol}, nil
}

// CreatePolicy creates a policy
func (s *Server) CreatePolicy(ctx context.Context, p *policy.Policy) (*policy.Policy, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	p.Id = id.String()
	err = s.DB.Insert(p)
	if err != nil {
		return nil, err
	}
	new, err := s.GetPolicy(ctx, &policy.IDQuery{Id: p.Id})
	if err != nil {
		return nil, err
	}
	return new, nil
}

// UpdatePolicy overwrites the existing policy
func (s *Server) UpdatePolicy(ctx context.Context, p *policy.Policy) (*policy.Policy, error) {
	err := s.DB.Update(p)
	if err != nil {
		return nil, err
	}
	new, err := s.GetPolicy(ctx, &policy.IDQuery{Id: p.Id})
	if err != nil {
		return nil, err
	}
	return new, nil
}

// PatchPolicy patches the given fields in the existing policy
func (s *Server) PatchPolicy(ctx context.Context, p *policy.Policy) (*policy.Policy, error) {
	cp, err := s.GetPolicy(ctx, &policy.IDQuery{Id: p.Id})
	if err != nil {
		return nil, err
	}
	err = mergo.Merge(p, cp)
	if err != nil {
		return nil, err
	}
	err = s.DB.Update(p)
	if err != nil {
		return nil, err
	}
	ps, err := s.GetPolicy(ctx, &policy.IDQuery{Id: p.Id})
	if err != nil {
		return nil, err
	}
	return ps, nil
}

// DeletePolicy deletes a policy by ID
func (s *Server) DeletePolicy(ctx context.Context, q *policy.IDQuery) (*policy.Empty, error) {
	err := s.DB.Delete(&policy.Policy{Id: q.Id})
	return &policy.Empty{}, err
}
