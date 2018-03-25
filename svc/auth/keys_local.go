package auth

import (
	"encoding/json"
	fmt "fmt"
	"strconv"
	"time"

	"crypto/rand"
	"crypto/rsa"

	"github.com/go-pg/pg"
	"github.com/kubecorp/coral/config"
	entity "github.com/kubecorp/coral/sdk/go/entity"
	log "github.com/sirupsen/logrus"
	context "golang.org/x/net/context"
	jose "gopkg.in/square/go-jose.v2"
)

// LocalKeyManager manages the local keys
type LocalKeyManager struct {
	Config      *config.ServerConfig
	PublicJWKs  map[string]jose.JSONWebKey
	PrivateJWKs map[string]jose.JSONWebKey
	DB          *pg.DB
}

type dbRSAKey struct {
	Id        string
	Key       []byte
	KeyID     string
	Use       string
	Algorithm string
}

func (pk *dbRSAKey) ToWebKey() (*jose.JSONWebKey, error) {
	var rk rsa.PrivateKey
	err := json.Unmarshal(pk.Key, &rk)
	if err != nil {
		return nil, err
	}
	return &jose.JSONWebKey{
		Key:       &rk,
		Use:       pk.Use,
		Algorithm: pk.Algorithm,
		KeyID:     pk.KeyID,
	}, nil
}

func webKeyToDB(wk *jose.JSONWebKey) (*dbRSAKey, error) {
	rsk, ok := wk.Key.(rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("prolem casting key type")
	}
	key, err := json.Marshal(rsk)
	if err != nil {
		return nil, err
	}
	return &dbRSAKey{
		Id:        wk.KeyID,
		Key:       key,
		KeyID:     wk.KeyID,
		Use:       wk.Use,
		Algorithm: wk.Algorithm,
	}, nil
}

func privToPublic(wk *jose.JSONWebKey) (*jose.JSONWebKey, error) {
	rsk, ok := wk.Key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("prolem casting key type")
	}
	return &jose.JSONWebKey{
		Key:       &rsk.PublicKey,
		KeyID:     wk.KeyID,
		Algorithm: wk.Algorithm,
		Use:       "public",
	}, nil
}

// Migrate runs schema migration on the DB
func (l *LocalKeyManager) Migrate() error {
	for _, model := range []interface{}{&dbRSAKey{}} {
		err := l.DB.CreateTable(model, nil)
		if err != nil {
			return err
		}
	}
	return nil
}

// VerifySignature implements the go-oidc interface and validates a JWT signature
func (l *LocalKeyManager) VerifySignature(ctx context.Context, jwt string) (bool, *IDToken, error) {
	jws, err := jose.ParseSigned(jwt)
	if err != nil {
		return false, nil, fmt.Errorf("verify signature: malformed jwt: %v", err)
	}
	var b []byte
	for _, val := range l.PublicJWKs {
		if b, err = jws.Verify(&val); err == nil {
			var token IDToken
			if err := json.Unmarshal(b, &token); err != nil {
				return false, nil, fmt.Errorf("oidc: failed to unmarshal claims: %v", err)
			}
			return true, &token, err
		}
	}
	return false, nil, fmt.Errorf("could not verify signature")
}

// CreateKeys creates a arbitary number of RSA key sets
func (l *LocalKeyManager) CreateKeys(num int) error {
	log.Infof("creating %v keys", num)
	for i := 1; i <= num; i++ {
		reader := rand.Reader
		bitSize := 2048

		key, err := rsa.GenerateKey(reader, bitSize)
		if err != nil {
			return err
		}
		uid := strconv.FormatInt(time.Now().Unix(), 10)
		b, err := json.Marshal(key)
		if err != nil {
			return err
		}
		log.Info("key id: ", uid)
		dbKey := dbRSAKey{Id: uid, Key: b, KeyID: uid, Algorithm: "RS256", Use: "private"}
		err = l.DB.Insert(&dbKey)
		if err != nil {
			return err
		}
		wk, err := dbKey.ToWebKey()
		if err != nil {
			return err
		}
		l.PrivateJWKs[uid] = *wk
		pub, err := privToPublic(wk)
		if err != nil {
			return err
		}
		l.PublicJWKs[uid] = *pub
		log.Infof("created new key set: %v", uid)
		time.Sleep(1 * time.Second)
	}
	return nil
}

// RotateKeys adds a new jwk RSA set and deletes the oldest
// TODO wash me
func (l *LocalKeyManager) RotateKeys() error {
	log.Info("rotating keys...")
	var jwks []dbRSAKey
	err := l.DB.Model(&jwks).Select()
	if err != nil {
		return err
	}
	log.Debugf("current keys: %+v", jwks)
	lowestID := int64(0)
	lowestJWK := dbRSAKey{}
	for _, k := range jwks {
		if lowestID == int64(0) {
			i, err := strconv.ParseInt(k.KeyID, 10, 64)
			if err != nil {
				return err
			}
			lowestID = i
			lowestJWK = k
			continue
		}
		i, err := strconv.ParseInt(k.KeyID, 10, 64)
		if err != nil {
			return err
		}
		if i < lowestID {
			lowestID = i
			lowestJWK = k
		}
	}
	log.Info("deleting keys: ", lowestJWK.KeyID)
	err = l.DB.Delete(&lowestJWK)
	if err != nil {
		return err
	}
	log.Info("creating new key set...")
	err = l.CreateKeys(1)
	if err != nil {
		return err
	}
	return l.UpdateCache()
}

// UpdateCache updates the key cache
func (l *LocalKeyManager) UpdateCache() error {
	jwks, err := l.GetSigningKeys()
	if err != nil {
		return err
	}
	log.Debugf("current database key set: %+v", jwks)
	privateKeys := map[string]jose.JSONWebKey{}
	publicKeys := map[string]jose.JSONWebKey{}
	for _, k := range jwks {
		privateKeys[k.KeyID] = k
		pub, err := privToPublic(&k)
		if err != nil {
			return err
		}
		publicKeys[k.KeyID] = *pub
	}
	l.PrivateJWKs = privateKeys
	l.PublicJWKs = publicKeys
	return nil
}

// GetSigningKeys fetches all private signing keys
func (l *LocalKeyManager) GetSigningKeys() ([]jose.JSONWebKey, error) {
	var dbwks []dbRSAKey
	jwks := []jose.JSONWebKey{}
	err := l.DB.Model(&dbwks).Select()
	if err != nil {
		return jwks, err
	}
	for _, k := range dbwks {
		wk, err := k.ToWebKey()
		if err != nil {
			return jwks, err
		}
		jwks = append(jwks, *wk)
	}
	return jwks, nil
}

// GetPublic fetches the public signing keys
func (l *LocalKeyManager) GetPublic() ([]jose.JSONWebKey, error) {
	var dbwks []dbRSAKey
	jwks := []jose.JSONWebKey{}
	err := l.DB.Model(&dbwks).Select()
	if err != nil {
		return jwks, err
	}
	for _, k := range dbwks {
		wk, err := k.ToWebKey()
		if err != nil {
			fmt.Println("cannot convert to web key: ", err)
			return jwks, err
		}
		pub, err := privToPublic(wk)
		if err != nil {
			fmt.Println("cannot convert to private to public: ", err)
			return jwks, err
		}
		jwks = append(jwks, *pub)
	}
	return jwks, nil
}

// GetSigningKey returns the most recent signing key
// TODO: write better query
func (l *LocalKeyManager) GetSigningKey() (jose.JSONWebKey, error) {
	var jwk jose.JSONWebKey
	var dbwks []dbRSAKey
	err := l.DB.Model(&dbwks).Select()
	if err != nil {
		return jwk, err
	}

	highestID := int64(0)
	highestJWK := dbRSAKey{}
	for _, k := range dbwks {
		if highestID == int64(0) {
			i, err := strconv.ParseInt(k.KeyID, 10, 64)
			if err != nil {
				return jwk, err
			}
			highestID = i
			highestJWK = k
			continue
		}
		i, err := strconv.ParseInt(k.KeyID, 10, 64)
		if err != nil {
			return jwk, err
		}
		if i > highestID {
			highestID = i
			highestJWK = k
		}
	}
	wk, err := highestJWK.ToWebKey()
	if err != nil {
		return jwk, err
	}
	return *wk, nil
}

// SignEntity signs an entity with the most recent signing key
func (l *LocalKeyManager) SignEntity(e *entity.Entity) (string, error) {
	signingKey, err := l.GetSigningKey()
	if err != nil {
		return "", err
	}
	log.Debugf("signing with key: %+v", signingKey)
	sk := jose.SigningKey{Algorithm: jose.RS256, Key: signingKey}
	signer, err := jose.NewSigner(sk, &jose.SignerOptions{})
	if err != nil {
		return "", err
	}

	token := IDToken{
		Issuer:   l.Config.Issuer,
		Expiry:   time.Now().Unix() + l.Config.TokenTTL,
		IssuedAt: time.Now().Unix(),
		Subject:  e.Id,
		Ext:      e.GetAttributes(),
	}
	b, err := json.Marshal(token)
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign(b)
	tokenString, err := jws.CompactSerialize()
	return tokenString, err
}
