package billing

import (
	"context"
	"fmt"

	"github.com/go-pg/pg"

	"github.com/aunem/coral/sdk/go/billing"
)

// Server represents a billing server
type Server struct {
	DB     *pg.DB
	ReadDB *pg.DB
}

// NewServer returns a new billing server
func NewServer(db, readDB *pg.DB) (*Server, error) {
	s := &Server{
		DB:     db,
		ReadDB: readDB,
	}
	if err := s.Migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

// Migrate runs schema migration on the DB
func (s *Server) Migrate() error {
	for _, model := range []interface{}{billing.Account{}} {
		err := s.DB.CreateTable(model, nil)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) Bill(ctx context.Context, req *billing.BillingRequest) (*billing.BillingResponse, error) {
	return nil, fmt.Errorf("not yet implemented")
}

func (s *Server) GetAccount(ctx context.Context, q *billing.IDQuery) (*billing.Account, error) {
	return nil, fmt.Errorf("not yet implemented")
}

func (s *Server) ListAccounts(ctx context.Context, q *billing.ListQuery) (*billing.Accounts, error) {
	return nil, fmt.Errorf("not yet implemented")
}

func (s *Server) CreateAccount(ctx context.Context, a *billing.Account) (*billing.Account, error) {
	return nil, fmt.Errorf("not yet implemented")
}

func (s *Server) UpdateAccount(ctx context.Context, a *billing.Account) (*billing.Account, error) {
	return nil, fmt.Errorf("not yet implemented")
}

func (s *Server) PatchAccount(ctx context.Context, a *billing.Account) (*billing.Account, error) {
	return nil, fmt.Errorf("not yet implemented")
}

func (s *Server) DeleteAccount(ctx context.Context, a *billing.IDQuery) (*billing.Empty, error) {
	return nil, fmt.Errorf("not yet implemented")
}
