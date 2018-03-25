package auth

import (
	"context"
	"encoding/json"
	fmt "fmt"

	oidc "github.com/coreos/go-oidc"
	"github.com/kubecorp/coral/sdk/go/issuer"
	issuersvc "github.com/kubecorp/coral/svc/issuer"
	ocontext "golang.org/x/net/context"
)

// RemoteKeyManager implements the validation of JWTs and the retrieval and caching of their
// signing keys
type RemoteKeyManager struct {
	JWKCache      map[string]oidc.KeySet
	IssuerManager *issuersvc.Server
}

// VerifyToken is the primary AuthN method that takes a token, looks up its issuer,
// grabs the keys and verifies the sig
func (j *RemoteKeyManager) VerifyToken(tokenString, issuer string) (bool, *IDToken, error) {
	keySet, err := j.FindPublicKeys(issuer)
	if err != nil {
		return false, nil, err
	}
	payload, err := keySet.VerifySignature(context.Background(), tokenString)
	if err != nil {
		return false, nil, err
	}
	// TODO we need to verify the algorithm? https://github.com/coreos/go-oidc/blob/v2/verify.go#L228
	var token IDToken
	if err := json.Unmarshal(payload, &token); err != nil {
		return false, nil, fmt.Errorf("oidc: failed to unmarshal claims: %v", err)
	}
	return false, &token, nil
}

func (j *RemoteKeyManager) GetKeySet() (*oidc.KeySet, error) {
	return nil, nil
}

// FindPublicKeys takes an issuer and attempts to retrieve the public key set for it by first checking
// the cache, then if necessary pulling the jwksUri that is registered for the issuer
func (j *RemoteKeyManager) FindPublicKeys(issuerName string) (oidc.KeySet, error) {
	var err error
	// check if there is an issuer record
	issuers, err := j.IssuerManager.ListIssuers(context.Background(), &issuer.Query{Name: issuerName})
	if err != nil {
		return nil, err
	}
	if len(issuers.Issuers) != 1 {
		return nil, fmt.Errorf("issuer not found, must register issuer first")
	}
	iss := issuers.Issuers[0]
	var k oidc.KeySet
	var ok bool
	if k, ok = j.JWKCache[issuerName]; !ok {
		k, err = j.RefreshKey(iss)
		if err != nil {
			return nil, err
		}
	}
	return k, nil
}

// RefreshKey refreshes the local cache with the signing keys in the issuers jwksUri
func (j *RemoteKeyManager) RefreshKey(issuer *issuer.Issuer) (oidc.KeySet, error) {
	set := oidc.NewRemoteKeySet(ocontext.Background(), issuer.GetJwksUri())
	return set, nil
}
