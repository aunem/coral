package issuer

import (
	"github.com/go-pg/pg"
	"github.com/imdario/mergo"
	"github.com/kubecorp/coral/sdk/go/issuer"
	"github.com/satori/go.uuid"
	context "golang.org/x/net/context"
)

// Server is the implementation of the grpc interface for issuer.proto
type Server struct {
	DB *pg.DB
}

// Migrate runs schema migration on the DB
func (s *Server) Migrate() error {
	for _, model := range []interface{}{&issuer.Issuer{}} {
		err := s.DB.CreateTable(model, nil)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetIssuer gets an issuer by ID
func (s *Server) GetIssuer(ctx context.Context, q *issuer.IDQuery) (*issuer.Issuer, error) {
	i := issuer.Issuer{Id: q.Id}
	err := s.DB.Select(&i)
	return &i, err
}

// ListIssuers lists issuers by name or issuer host, leave blank to list all
func (s *Server) ListIssuers(ctx context.Context, q *issuer.Query) (*issuer.Issuers, error) {
	var issuers []issuer.Issuer
	err := s.DB.Model(&issuers).Select()
	if err != nil {
		return nil, err
	}
	niss := []*issuer.Issuer{}
	for _, i := range issuers {
		niss = append(niss, &i)
	}
	return &issuer.Issuers{niss}, nil
}

// CreateIssuer creates an issuer
func (s *Server) CreateIssuer(ctx context.Context, i *issuer.Issuer) (*issuer.Issuer, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	i.Id = id.String()
	err = s.DB.Insert(i)
	if err != nil {
		return nil, err
	}
	iNew, err := s.GetIssuer(ctx, &issuer.IDQuery{Id: i.Id})
	if err != nil {
		return nil, err
	}
	return iNew, nil
}

// UpdateIssuer replaces the current issuer by ID
func (s *Server) UpdateIssuer(ctx context.Context, i *issuer.Issuer) (*issuer.Issuer, error) {
	err := s.DB.Update(i)
	if err != nil {
		return nil, err
	}
	new, err := s.GetIssuer(ctx, &issuer.IDQuery{Id: i.Id})
	if err != nil {
		return nil, err
	}
	return new, nil
}

// PatchIssuer patches just the fields supplied for the given ID
func (s *Server) PatchIssuer(ctx context.Context, i *issuer.Issuer) (*issuer.Issuer, error) {
	ci, err := s.GetIssuer(ctx, &issuer.IDQuery{Id: i.Id})
	if err != nil {
		return nil, err
	}
	err = mergo.Merge(i, ci)
	if err != nil {
		return nil, err
	}
	err = s.DB.Update(i)
	if err != nil {
		return nil, err
	}
	is, err := s.GetIssuer(ctx, &issuer.IDQuery{Id: i.Id})
	if err != nil {
		return nil, err
	}
	return is, nil
}

// DeleteIssuer deletes an issuer by ID
func (s *Server) DeleteIssuer(ctx context.Context, q *issuer.IDQuery) (*issuer.Empty, error) {
	err := s.DB.Delete(&issuer.Issuer{Id: q.Id})
	return &issuer.Empty{}, err
}
