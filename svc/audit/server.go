package audit

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-pg/pg"

	"github.com/adjust/rmq"
	"github.com/aunem/coral/sdk/go/audit"
	"github.com/aunem/coral/sdk/go/auth"
	"github.com/aunem/coral/sdk/go/entity"
	authsvc "github.com/aunem/coral/svc/auth"
)

// Server represents an audit server
type Server struct {
	DB     *pg.DB
	ReadDB *pg.DB
	Queue  rmq.Queue
	Auth   *authsvc.Server
}

// NewServer creates a new audit server
func NewServer(db, readDB *pg.DB, queue rmq.Queue, a *authsvc.Server) (*Server, error) {
	s := &Server{
		DB:     db,
		ReadDB: readDB,
		Queue:  queue,
		Auth:   a,
	}
	err := s.Migrate()
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Migrate runs schema migration on the DB
func (s *Server) Migrate() error {
	for _, model := range []interface{}{&audit.AuditRecord{}} {
		err := s.DB.CreateTable(model, nil)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetRecord retrieves an audit record
func (s *Server) GetRecord(ctx context.Context, q *audit.IDQuery) (*audit.AuditRecord, error) {
	return nil, fmt.Errorf("not yet implemented")
}

// ListRecords records retrieves a list of records
func (s *Server) ListRecords(ctx context.Context, q *audit.ListQuery) (*audit.AuditRecords, error) {
	return nil, fmt.Errorf("not yet implemented")
}

// CreateRecord creates an audit record by publishing it to a queue, which a worker then consumes
func (s *Server) CreateRecord(ctx context.Context, r *audit.AuditRecord) (*entity.Empty, error) {
	areq, err := authsvc.GRPCToAuthRequest(ctx)
	if err != nil {
		return nil, err
	}
	areq.Grpc = &auth.GRPCRequest{
		Service: "audit",
		Method:  "CreateRecord",
	}
	_, err = s.Auth.AuthorizeLocal(ctx, areq)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	ok := s.Queue.PublishBytes(b)
	if !ok {
		return nil, fmt.Errorf("could not publish to queue")
	}
	return nil, nil
}

// RetireRecords retires records to cold storage
func (s *Server) RetireRecords(ctx context.Context, q *audit.RetireQuery) (*entity.Empty, error) {
	return nil, fmt.Errorf("not yet implemented")
}
