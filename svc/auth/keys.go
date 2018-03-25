package auth

import (
	"encoding/base64"
	"encoding/json"
	fmt "fmt"
	"strings"

	"github.com/kubecorp/coral/config"
	entity "github.com/kubecorp/coral/sdk/go/entity"
	issuer "github.com/kubecorp/coral/sdk/go/issuer"
	entitysvc "github.com/kubecorp/coral/svc/entity"
	issuersvc "github.com/kubecorp/coral/svc/issuer"
	log "github.com/sirupsen/logrus"
	context "golang.org/x/net/context"
)

// KeyManager authenticates signed keys whether local or remote
type KeyManager struct {
	LocalKeys     *LocalKeyManager
	RemoteKeys    *RemoteKeyManager
	EntityManager *entitysvc.Server
	IssuerManager *issuersvc.Server
	Config        *config.ServerConfig
}

// IDToken is an representation of the JWT body in OIDC
type IDToken struct {
	Issuer     string            `json:"iss"`
	Subject    string            `json:"sub"`
	Email      string            `json:"email"`
	Audience   string            `json:"aud"`
	Expiry     int64             `json:"exp"`
	IssuedAt   int64             `json:"iat"`
	Nonce      string            `json:"nonce"`
	AtHash     string            `json:"at_hash"`
	Attributes map[string]string `json:"attr"`
	Ext        map[string]string `json:"ext"`
}

// Authenticate will determin if the token is local or remote and verify the signature, returning the associated entity.
func (k *KeyManager) Authenticate(ctx context.Context, jwtEnc string) (*entity.Entity, error) {
	iss, err := k.PeekIssuer(jwtEnc)
	if err != nil {
		return nil, err
	}
	var allowed bool
	var token *IDToken
	if iss == k.Config.Issuer {
		allowed, token, err = k.LocalKeys.VerifySignature(ctx, jwtEnc)
		if err != nil {
			return nil, err
		}
	} else {
		allowed, token, err = k.RemoteKeys.VerifyToken(jwtEnc, iss)
		if err != nil {
			return nil, err
		}
	}
	if !allowed {
		return nil, fmt.Errorf("request not allowed")
	}
	e, err := k.TokenToEntity(token)
	if err != nil {
		return nil, err
	}
	return e, nil
}

// PeekIssuer is a lightwieght parsing method to grab the issuer claim so the appropriate JWK
// public keys can be found
func (k *KeyManager) PeekIssuer(jwtEnc string) (string, error) {
	parts := strings.Split(jwtEnc, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("token contains an invalid number of segments")
	}

	var err error
	// parse Claims
	var claimBytes []byte
	seg := parts[1]
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	claimBytes, err = base64.URLEncoding.DecodeString(seg)
	if err != nil {
		return "", err
	}
	var x map[string]interface{}
	json.Unmarshal(claimBytes, &x)
	log.Debugf("claim bytes: %v \n", x)
	var iss string
	var ok bool
	if iss, ok = x["iss"].(string); ok {
		return iss, nil
	}
	return "", fmt.Errorf("issuer not found")
}

// TokenToEntity Converts an IDToken to an Entity
func (k *KeyManager) TokenToEntity(token *IDToken) (e *entity.Entity, err error) {
	ctx := context.Background()
	if token.Issuer == k.Config.Issuer {
		e, err = k.EntityManager.GetEntity(ctx, &entity.IDQuery{Id: token.Subject})
		if err != nil {
			return nil, err
		}
	} else {
		i, err := k.IssuerManager.ListIssuers(ctx, &issuer.Query{Issuer: token.Issuer})
		if err != nil {
			return nil, err
		}
		if len(i.Issuers) != 1 {
			return nil, fmt.Errorf("query did not return one issuer")
		}
		iss := i.Issuers[0]
		c := entity.JWTAuth{Name: iss.Name, Claims: token.FlattenClaims()}
		e, err = k.EntityManager.GetEntity(context.Background(), &entity.IDQuery{Claims: &c})
		if err != nil {
			return nil, err
		}
	}
	return
}

// FlattenClaims taks an IDToken and flattens all claims to a simple map
func (i *IDToken) FlattenClaims() map[string]string {
	m := map[string]string{
		"sub":   i.Subject,
		"email": i.Email,
	}
	for k, v := range i.Ext {
		m[k] = v
	}
	return m
}
