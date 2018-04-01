package entity

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/aunem/coral/config"
	"github.com/aunem/coral/sdk/go/entity"
	"github.com/aunem/coral/util"
	"github.com/go-pg/pg"
	"github.com/imdario/mergo"
	"github.com/satori/go.uuid"
)

// Server is the implementation of the grpc interface for issuer.proto
type Server struct {
	DB *pg.DB
}

// NewServer creates a new server, migrates the database, and provisions the root client if it doesn't exist
// TODO: add persistence layer to clean up
func NewServer(c *config.ServerConfig, db *pg.DB) (*Server, error) {
	s := &Server{
		DB: db,
	}
	err := s.Migrate()
	if err != nil {
		return nil, err
	}
	var entities []entity.Entity
	err = s.DB.Model(&entities).
		Where(`attributes \?& array['name']`).
		Limit(1).
		Select()
	if err != nil {
		return nil, err
	}
	exists := false
	if c.RootName == "" {
		log.Infof("root name does not exist, using default: root")
		c.RootName = "root"
	}
	if c.RootPass == "" {
		log.Infof("root pass does not exist creating random")
		c.RootPass = util.RandStringBytes(20)
		log.Debugf("root pass: ", c.RootPass)
	}
	for _, e := range entities {
		if val, ok := e.Attributes["name"]; ok {
			if val == c.RootName {
				exists = true
			}
		}
	}
	if !exists {
		e := &entity.Entity{
			Attributes: map[string]string{
				"name": c.RootName,
			},
			Authentication: &entity.EntityAuth{
				Basic: []*entity.BasicAuth{
					&entity.BasicAuth{
						Id:     c.RootName,
						Secret: c.RootPass,
					},
				},
			},
		}
		id, err := uuid.NewV4()
		if err != nil {
			return nil, err
		}
		e.Id = id.String()
		err = s.DB.Insert(e)
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Migrate runs schema migration on the DB
func (s *Server) Migrate() error {
	for _, model := range []interface{}{&entity.Entity{}} {
		err := s.DB.CreateTable(model, nil)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) GetEntity(ctx context.Context, q *entity.IDQuery) (*entity.Entity, error) {
	if q.Id != "" {
		e := entity.Entity{Id: q.Id}
		err := s.DB.Select(&e)
		return &e, err
	}
	if q.KeyId != "" {
		s.DB.OnQueryProcessed(func(event *pg.QueryProcessedEvent) {
			query, err := event.FormattedQuery()
			if err != nil {
				panic(err)
			}

			log.Debugf("SQL QUERY: %s %s", time.Since(event.StartTime), query)
		})
		var e entity.Entity
		jq := fmt.Sprintf(`[{"id": "%s"}]`, q.KeyId)
		err := s.DB.Model(&e).
			Where(`authentication->'basic' @> ?`, jq).
			Limit(1).
			Select()
		if err != nil {
			return nil, err
		}
		return &e, nil
	}
	if q.Claims != nil { //TODO: wash me
		s.DB.OnQueryProcessed(func(event *pg.QueryProcessedEvent) {
			query, err := event.FormattedQuery()
			if err != nil {
				panic(err)
			}

			log.Debugf("SQL QUERY: %s %s", time.Since(event.StartTime), query)
		})
		var es []entity.Entity
		jq := fmt.Sprintf(`[{"name": "%s"}]`, q.Claims.Name)
		err := s.DB.Model(&es).
			Where(`authentication->'jwt' @> ?`, jq).
			Select()
		if err != nil {
			return nil, err
		}
		for _, e := range es {
			for _, a := range e.Authentication.Jwt {
				if a.Name != q.Claims.Name {
					continue
				}
				isMatch := false
				for k, v := range a.Claims {
					keyMatch := false
					for key, val := range q.Claims.Claims {
						if k == key && v == val {
							keyMatch = true
						}
					}
					isMatch = keyMatch
				}
				if isMatch {
					return &e, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("not found")
}

func (s *Server) ListEntities(ctx context.Context, q *entity.Query) (*entity.Entities, error) {
	var entities []entity.Entity
	err := s.DB.Model(&entities).
		Where(`attributes \?& ?`, pg.Array(q.Attributes)). //TODO: query by exact keys
		Limit(1).
		Select()
	if err != nil {
		return nil, err
	}
	nent := []*entity.Entity{}
	for _, e := range entities {
		nent = append(nent, &e)
	}
	return &entity.Entities{nent}, nil
}

func (s *Server) CreateEntity(ctx context.Context, e *entity.Entity) (*entity.Entity, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	e.Id = id.String()
	err = s.DB.Insert(e)
	if err != nil {
		return nil, err
	}
	eNew, err := s.GetEntity(ctx, &entity.IDQuery{Id: e.Id})
	if err != nil {
		return nil, err
	}
	return eNew, nil
}

func (s *Server) UpdateEntity(ctx context.Context, e *entity.Entity) (*entity.Entity, error) {
	err := s.DB.Update(e)
	if err != nil {
		return nil, err
	}
	new, err := s.GetEntity(ctx, &entity.IDQuery{Id: e.Id})
	if err != nil {
		return nil, err
	}
	return new, nil
}

func (s *Server) PatchEntity(ctx context.Context, e *entity.Entity) (*entity.Entity, error) {
	ce, err := s.GetEntity(ctx, &entity.IDQuery{Id: e.Id})
	if err != nil {
		return nil, err
	}
	err = mergo.Merge(e, ce)
	if err != nil {
		return nil, err
	}
	err = s.DB.Update(e)
	if err != nil {
		return nil, err
	}
	is, err := s.GetEntity(ctx, &entity.IDQuery{Id: e.Id})
	if err != nil {
		return nil, err
	}
	return is, nil
}

func (s *Server) DeleteEntity(ctx context.Context, q *entity.IDQuery) (*entity.Empty, error) {
	err := s.DB.Delete(&entity.Entity{Id: q.Id})
	return &entity.Empty{}, err
}
