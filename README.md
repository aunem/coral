# Coral

* **NOTE:** Coral is pre-alpha and under heavy development

Secure, audit, and bill your API.

Coral aims to be an added layer ontop of OIDC and JWK based signing servers. While OIDC provides a nice authN layer there is a missing authZ compoenent. Coral fills this gap and further grants auditing and billing support.

Coral is a audit centric auth correlation engine with native resource billing capablity.

## Tenants

* Observability
* Applications are first world citizens
* Audit centric
* Simple authorization
* Billing enabled
* Globally replicated
* Low latency
* Warn over rescrict
* No Pagentry

## Correlation

Coral works off the notion that all authentication is merely correlation. Coral does this by using correlation records to match JWTs.

Any signed entity can be correlated to an internal entity record. An entity is simply a collection of attributes:

entity.yaml
```yaml
version: alphav1
id: 7453d762-1e2a-455b-b5e7-a308fa38eca5
attributes:
  type: user
  username: myuser
  role: admin
  teams: "myteam1,myteam2"
authentication:
  basic:
  - id: jim@google.com
    secret: myhashedpass
  jwt:
  - name: google
    claims:
      sub: jimbo
      email: jim@google.com
  - name: dex
    claims:
      sub: jim@github.com
billing:
- account: 3353dde62-1e2a-455b-b5we7-a308fdsf28eca5
  id: stripeuuid1234

```

The issuer must be previously assigned an issuer record:

issuer.yaml
```yaml
version: alphav1
id: 01292358-9b1a-45ea-a847-9c7e8f1f510c
name: google
issuer: auth.myhost.com
jwksUri: "/.well-known/jwks.json"
issuerClaim: issuer
subjectClaim: sub
expiresClaim: expires
```

This could be from an OIDC server such as Google Login or a simple signing server like Ink. The keys must be returned in the form: 

```json
{
 "keys": [
  {
   "kty": "RSA",
   "alg": "RS256",
   "use": "sig",
   "kid": "b0abc52a7265f6066d28db73164ddc0f206c24bc",
   "n": "wJxiXxczBfuonIp2PWRopKTZ3YEEQR1TOgSqjaVTtaFprhY621G-9S0x86SM6roD7Qb5itj_lC8OvOggYUPlmioz",
   "e": "AQAB"
  },
  {
   "kty": "RSA",
   "alg": "RS256",
   "use": "sig",
   "kid": "d04d14925eef1a7a61ed76431bf4d1e5e109afdf",
   "n": "lBipUcAkDLtS_r9otx18gcEDY1J559Fb6Mrt5k8P4I1G_C5Kidu2zhd04wOB0N3VpOcNp84LM_7zRsG9-_nYNtvntD_TYr",
   "e": "AQAB"
  },
  {
   "kty": "RSA",
   "alg": "RS256",
   "use": "sig",
   "kid": "30f9d5f1dc78c701191ace24f8a5476bb78a3d15",
   "n": "pI0D93U-_yCcey5phPNpyZnTdwR7f17kufPLLz0WQX2LJh7q8GSZZPtp4txOnBjYDTJkG16tN2uqdPrSuyDE_1XsIGcpnOU",
   "e": "AQAB"
  }
 ]
}
```

This follows the OIDC format with past, present, and future JWK public signing keys being returned.

## Authorization
Coral implements ABAC authorization. Entity attributes use a simple wildcard matching to request attributes on network resources. Both http and grpc transport are supported. The request attibutes are easily extensible to fit any need.

dev_group.yaml
```yaml
version: alphav1
name: devGroup
entityAttributes:
  username: myuser
  email: myuser@protonmail.com
  group: mygroup*
effect: allow
requestAttributes:
  headers:
    MY_HEADER: "*myval"
  cidr: "0.0.0.0/0"
  host: "*.myhost.com"
http:
- path: /mypath
  action: GET
  query:
    user: "*",
  toll: 0.01
```

admin_role.yaml
```yaml
version: alphav1
name: adminRole
entityAttributes:
  "role": "admin"
effect: allow
http:
- path: /mypath
  actions: ["GET"]
  requestAttributes:
    query: 
      user: "*"
```

all_open.yaml
```yaml
version: alphav1
name: openPolicy
entityAttributes:
  "*": "*"
effect: allow
http:
- path: "*"
  actions: ["*"]
```

All parameters are deny by default except request attributes, which if left blank allow all.

## Billing
Coral enables simple API billing through its correlation system. An entity accessing a resource can be billed at the moment of authorization or on a successful request. // How do we get the response? request corelation id?

Billing happens through an account entity. An account is created an correlated to an email?

Currently Stripe is supported.

account.yaml
```yaml
name: mystripe
type: stripe
stripeID: mystripeid123
```

Billing rules can then be created:

billing.yaml
```yaml
version: v1alpha
name: newbilling
requestAttributes:
  host: "*.myhost"
http:
- path: queue/messages
  actions: ["GET"]
  cost: '0.01'
  per: '100'
- path: auth/users
  actions: ["POST"]
  cost: '0.03'
  per: '1000'
```

Coral will supply a resource response endpoint that can be used in conjunction with a request id to ensure entities aren't billed for anything but 2xx responses.

## Gateway

Coral is made to be pluggable into any generic gateway system. Whether it be Kong, traefik, or Envoy. It enables authn/z and api billing with a low very little overhead. Implementations coming soon.

## Auditing
All events are audited by default, allowing for fast conflict resolution and strict compliance. Coral will provide a number of audit backends.

## Transport

Coral is an HTTP and GRPC server. While most auth systems only use HTTP, Coral is cognizant of latency and allows gateways to leverage the high throughput low latency capablilites of GRPC.

Coral enforces best practices for network communication. SSL and nonces are required to protect against man in the middle attacks.

## Roadmap
[x] Entity correlation   
[x] ABAC   
[ ] Auditing   
[ ] Gateway integration   
[ ] Billing integration   
[ ] Anomoly detection   

## Contact Us
