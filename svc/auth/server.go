package auth

import (
	fmt "fmt"
	"strings"

	"encoding/base64"

	"github.com/aunem/coral/config"
	auth "github.com/aunem/coral/sdk/go/auth"
	entity "github.com/aunem/coral/sdk/go/entity"
	entitysvc "github.com/aunem/coral/svc/entity"
	log "github.com/sirupsen/logrus"
	context "golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

// Server handles AuthN/Z requests
type Server struct {
	Keys          *KeyManager
	Authorization *Authorization
	Entities      *entitysvc.Server
	Config        *config.ServerConfig
}

func newServer() *Server {
	return new(Server)
}

// AuthType represents a basic or bearer auth flow
type AuthType string

const (
	AuthTypeBasic  AuthType = "basic"
	AuthTypeBearer AuthType = "bearer"
)

// AuthHeader represents a parsed auth header
type AuthHeader struct {
	Type      AuthType
	EncString string
}

// Authenticate takes an AuthHeader and checks if it is authenticated
func (s *Server) Authenticate(ctx context.Context, a *AuthHeader) (*entity.Entity, error) {
	var e *entity.Entity
	var err error
	switch a.Type {
	case AuthTypeBasic:
		e, err = s.AuthenticateBasic(ctx, a.EncString)
		if err != nil {
			return nil, fmt.Errorf("basic auth failed")
		}
	case AuthTypeBearer:
		e, err = s.Keys.Authenticate(ctx, a.EncString)
		if err != nil {
			return nil, fmt.Errorf("bearer auth failed")
		}
	default:
		return nil, fmt.Errorf("auth header not valid")
	}
	return e, nil
}

// Authorize takes a JWT token, matches it to an entity and determines whether its eligable to
// access the networked resource and returns a parsed entity
// Requires the caller have priviledges to access
func (s *Server) Authorize(ctx context.Context, a *auth.AuthorizationRequest) (*auth.AuthorizationResponse, error) {
	var err error
	notAllowedResp := &auth.AuthorizationResponse{Allowed: false, Entity: nil}

	// Auth caller to check token
	log.Debugf("caller context: %+v \n", ctx)
	meta, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return notAllowedResp, grpc.Errorf(codes.Unauthenticated, "missing context metadata")
	}
	log.Debugf("caller metadata: %+v", meta)
	authHeader, err := s.ParseAuthHeader(HeadersToProto(meta))
	if err != nil {
		return notAllowedResp, grpc.Errorf(codes.Unauthenticated, "auth header not valid")
	}
	log.Debugf("caller auth header: %+v", authHeader)
	e, err := s.Authenticate(ctx, authHeader)
	if err != nil {
		return notAllowedResp, grpc.Errorf(codes.Unauthenticated, "entity not allowed to check token")
	}
	a0 := &auth.AuthorizationRequest{
		Http: &auth.HTTPRequest{
			Path:   "/authorize",
			Action: "POST",
		},
		Grpc: &auth.GRPCRequest{
			Service: "AuthService",
			Method:  "Authorize",
		},
		Headers: HeadersToProto(meta),
	}
	allowed, err := s.Authorization.Allowed(ctx, e, a0)
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, err.Error())
	}
	if !allowed {
		return nil, grpc.Errorf(codes.PermissionDenied, "entity not allowed to check token")
	}

	return s.AuthorizeLocal(ctx, a)
}

// AuthorizeLocal takes a JWT token, matches it to an entity and determines whether its eligable to
// access the networked resource and returns a parsed entity
// Does not require caller access, for internal use only
func (s *Server) AuthorizeLocal(ctx context.Context, a *auth.AuthorizationRequest) (*auth.AuthorizationResponse, error) {
	var err error
	notAllowedResp := &auth.AuthorizationResponse{Allowed: false, Entity: nil}

	log.Debugf("checking request: %+v", a)
	authHeader, err := s.ParseAuthHeader(a.Headers)
	if err != nil {
		return notAllowedResp, grpc.Errorf(codes.Unauthenticated, "auth header not valid")
	}
	log.Debugf("subject auth header: %+v", authHeader)
	e, err := s.Authenticate(ctx, authHeader)
	if err != nil {
		return notAllowedResp, grpc.Errorf(codes.Unauthenticated, "entity not authenticated")
	}
	allowed, err := s.Authorization.Allowed(ctx, e, a)
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, err.Error())
	}
	if !allowed {
		return nil, grpc.Errorf(codes.PermissionDenied, "entity not authorized")
	}
	return &auth.AuthorizationResponse{Allowed: true, Entity: e}, nil
}

// AuthorizeAndSign takes a JWT token, matches it to an entity and determines whether its eligable to
// access the networked resource and returns a signed JWT from this server with the entity claims
func (s *Server) AuthorizeAndSign(ctx context.Context, a *auth.AuthorizationRequest) (*auth.AuthorizationSigningResponse, error) {
	e, err := s.Authorize(ctx, a)
	if err != nil {
		return nil, err
	}
	jot, err := s.Keys.LocalKeys.SignEntity(e.Entity)
	if err != nil {
		return nil, err
	}
	log.Debug("signed entity: ", jot)
	return &auth.AuthorizationSigningResponse{
		Allowed: true,
		Jwt:     jot,
	}, nil
}

// Sign takes a remote JWT and exchanges it for an internal signed entity
func (s *Server) Sign(ctx context.Context, a *auth.SigningRequest) (*auth.SigningResponse, error) {
	log.Debugf("context: %+v \n", ctx)
	meta, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, grpc.Errorf(codes.Unauthenticated, "missing context metadata")
	}
	log.Debugf("metadata: %+v", meta)
	authHeader, err := s.ParseAuthHeader(HeadersToProto(meta))
	if err != nil {
		return nil, grpc.Errorf(codes.Unauthenticated, "auth header not valid")
	}
	log.Debugf("auth header: %+v", authHeader)
	e, err := s.Authenticate(ctx, authHeader)
	if err != nil {
		return nil, grpc.Errorf(codes.Unauthenticated, "entity not allowed to check token")
	}
	jot, err := s.Keys.LocalKeys.SignEntity(e)
	if err != nil {
		return nil, err
	}
	log.Debug("signed entity: ", jot)
	return &auth.SigningResponse{
		Jwt: jot,
	}, nil
}

// SignPayload signs an arbitrary payload
func (s *Server) SignPayload(ctx context.Context, a *auth.SigningPayloadRequest) (*auth.SigningPayloadResponse, error) {
	return nil, grpc.Errorf(codes.Unimplemented, "not yet implemented")
}

// SignBasic takes basic auth and returns a JWT
func (s *Server) SignBasic(ctx context.Context, a *auth.Empty) (*auth.SigningResponse, error) {
	notAllowedResp := &auth.SigningResponse{}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return notAllowedResp, grpc.Errorf(codes.Unauthenticated, "could not fetch incomming request metadata")
	}
	var h []string
	h, ok = md["authorization"]
	if !ok {
		return notAllowedResp, grpc.Errorf(codes.Unauthenticated, "authorization header not present")
	}
	if len(h) != 1 {
		return notAllowedResp, grpc.Errorf(codes.Unauthenticated, "header length is wrong")
	}
	header := h[0]
	encr := strings.Split(header, " ")
	if len(encr) != 2 {
		return notAllowedResp, grpc.Errorf(codes.Unauthenticated, "header not valid")
	}
	enc := encr[1]
	ent, err := s.AuthenticateBasic(ctx, strings.TrimSpace(enc))
	if err != nil {
		return notAllowedResp, grpc.Errorf(codes.Unauthenticated, err.Error())
	}
	jwt, err := s.Keys.LocalKeys.SignEntity(ent)
	if err != nil {
		return notAllowedResp, grpc.Errorf(codes.Unauthenticated, err.Error())
	}

	return &auth.SigningResponse{Jwt: jwt}, nil
}

// EntityInfo returns info about a given JWT
func (s *Server) EntityInfo(ctx context.Context, a *auth.JWTEnc) (*entity.Entity, error) {
	return nil, grpc.Errorf(codes.Unimplemented, "not yet implemented")
}

// WellKnown returns a typical OIDC wellknown response
func (s *Server) WellKnown(ctx context.Context, a *auth.Empty) (*auth.WellKnownResponse, error) {
	return nil, grpc.Errorf(codes.Unimplemented, "not yet implemented")
}

// JWKs returns the public JWKs
func (s *Server) JWKs(ctx context.Context, a *auth.Empty) (*auth.JWKsResponse, error) {
	return nil, grpc.Errorf(codes.Unimplemented, "not yet implemented")
}

// AuthenticateBasic takes a id:secret basic auth encoded string and checks if its valid returning the entity
func (s *Server) AuthenticateBasic(ctx context.Context, encodedString string) (*entity.Entity, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encodedString))
	if err != nil {
		return nil, fmt.Errorf("could not decode auth string")
	}
	split := strings.Split(string(decoded), ":")
	if len(split) != 2 {
		return nil, fmt.Errorf("not valid authorization header")
	}
	id := split[0]
	secret := split[1]

	e, err := s.Entities.GetEntity(ctx, &entity.IDQuery{KeyId: id})
	if err != nil {
		return nil, err
	}
	authorized := false
	for _, b := range e.Authentication.Basic {
		if (b.Id == id) && (b.Secret == secret) {
			authorized = true
		}
	}
	if !authorized {
		return nil, fmt.Errorf("not authorized")
	}
	return e, nil
}

// ParseAuthHeader parses the auth header from a set of headers
func (s *Server) ParseAuthHeader(headers map[string]*auth.HeaderVals) (*AuthHeader, error) {
	hclean := map[string][]string{}
	for k, v := range headers {
		hclean[strings.ToLower(k)] = v.Values
	}
	if _, ok := hclean["authorization"]; !ok {
		return nil, fmt.Errorf("missing authorization header")
	}
	if len(hclean["authorization"]) != 1 {
		return nil, fmt.Errorf("auth header not valid")
	}
	authHeader := hclean["authorization"][0]
	hsplit := strings.Split(authHeader, " ")
	if len(hsplit) != 2 {
		return nil, fmt.Errorf("auth header not valid")
	}
	enc := strings.TrimSpace(hsplit[1])
	typ := strings.TrimSpace(strings.ToLower(hsplit[0]))

	if typ != "basic" && typ != "bearer" {
		return nil, fmt.Errorf("auth header not valid")
	}
	var authType AuthType
	switch typ {
	case "basic":
		authType = AuthTypeBasic
	case "bearer":
		authType = AuthTypeBearer
	default:
		return nil, fmt.Errorf("auth header not valid")
	}
	return &AuthHeader{
		Type:      authType,
		EncString: enc,
	}, nil
}
