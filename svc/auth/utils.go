package auth

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/kubecorp/coral/sdk/go/auth"
	context "golang.org/x/net/context"
	"google.golang.org/grpc/metadata"
)

// HeadersToProto takes the request headers and maps them to the necesary protobuf structure
func HeadersToProto(headers map[string][]string) map[string]*auth.HeaderVals {
	hv := map[string]*auth.HeaderVals{}
	for k, v := range headers {
		hv[k] = &auth.HeaderVals{
			Values: v,
		}
	}
	return hv
}

// GRPCToAuthRequest takes an incoming GRPC request and produces an auth reqeust
func GRPCToAuthRequest(ctx context.Context) (*auth.AuthorizationRequest, error) {
	a := &auth.AuthorizationRequest{}
	meta, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("could not get metadata from request")
	}
	if val, ok := meta["host"]; ok {
		if len(val) > 0 {
			a.Host = val[0]
		}
	}
	headers := HeadersToProto(meta)
	a.Headers = headers

	return a, nil
}

// HTTPRequestToAuthRequest takes an incoming HTTP request and produces an auth request
func HTTPRequestToAuthRequest(req *http.Request) (*auth.AuthorizationRequest, error) {
	return nil, fmt.Errorf("not yet implemented")
}

// BasicToEnc takes an id/secret and b64 encodes it
func BasicToEnc(id string, secret string) string {
	cat := fmt.Sprintf("%s:%s", id, secret)
	encoded := base64.StdEncoding.EncodeToString([]byte(cat))
	return encoded
}
