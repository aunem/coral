package rpc

import (
	"fmt"

	"github.com/aunem/coral/sdk/go/auth"
	"github.com/aunem/coral/sdk/go/entity"
)

// TODO: need to figure out how we handle different service addresses

// CoralClient is a high level struct holding all of the services
type CoralClient struct {
	AuthClient   *auth.AuthServiceClient
	EntityClient *entity.EntityServiceClient
}

// NewCoralClient returns a new Coral auth server
func NewCoralClient() (*CoralClient, error) {
	return nil, fmt.Errorf("not yet implemented")
}
