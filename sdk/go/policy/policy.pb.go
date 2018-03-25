// Code generated by protoc-gen-go. DO NOT EDIT.
// source: api/policy.proto

/*
Package policy is a generated protocol buffer package.

It is generated from these files:
	api/policy.proto

It has these top-level messages:
	Policy
	RoutePolicy
	RequestAttributes
	MethodPolicy
	IDQuery
	Query
	Policies
	Empty
*/
package policy

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "google.golang.org/genproto/googleapis/api/annotations"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Policy struct {
	Id                string             `protobuf:"bytes,1,opt,name=id" json:"id,omitempty"`
	CreatedTime       int64              `protobuf:"varint,2,opt,name=createdTime" json:"createdTime,omitempty"`
	UpdateTime        int64              `protobuf:"varint,3,opt,name=updateTime" json:"updateTime,omitempty"`
	Name              string             `protobuf:"bytes,4,opt,name=name" json:"name,omitempty"`
	EntityAttributes  map[string]string  `protobuf:"bytes,5,rep,name=entityAttributes" json:"entityAttributes,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	Effect            string             `protobuf:"bytes,6,opt,name=effect" json:"effect,omitempty"`
	RequestAttributes *RequestAttributes `protobuf:"bytes,7,opt,name=requestAttributes" json:"requestAttributes,omitempty"`
	Http              []*RoutePolicy     `protobuf:"bytes,8,rep,name=http" json:"http,omitempty"`
	Grpc              []*MethodPolicy    `protobuf:"bytes,9,rep,name=grpc" json:"grpc,omitempty"`
}

func (m *Policy) Reset()                    { *m = Policy{} }
func (m *Policy) String() string            { return proto.CompactTextString(m) }
func (*Policy) ProtoMessage()               {}
func (*Policy) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Policy) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *Policy) GetCreatedTime() int64 {
	if m != nil {
		return m.CreatedTime
	}
	return 0
}

func (m *Policy) GetUpdateTime() int64 {
	if m != nil {
		return m.UpdateTime
	}
	return 0
}

func (m *Policy) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Policy) GetEntityAttributes() map[string]string {
	if m != nil {
		return m.EntityAttributes
	}
	return nil
}

func (m *Policy) GetEffect() string {
	if m != nil {
		return m.Effect
	}
	return ""
}

func (m *Policy) GetRequestAttributes() *RequestAttributes {
	if m != nil {
		return m.RequestAttributes
	}
	return nil
}

func (m *Policy) GetHttp() []*RoutePolicy {
	if m != nil {
		return m.Http
	}
	return nil
}

func (m *Policy) GetGrpc() []*MethodPolicy {
	if m != nil {
		return m.Grpc
	}
	return nil
}

type RoutePolicy struct {
	Path              string             `protobuf:"bytes,1,opt,name=path" json:"path,omitempty"`
	Query             map[string]string  `protobuf:"bytes,2,rep,name=query" json:"query,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	Actions           []string           `protobuf:"bytes,3,rep,name=actions" json:"actions,omitempty"`
	RequestAttributes *RequestAttributes `protobuf:"bytes,4,opt,name=requestAttributes" json:"requestAttributes,omitempty"`
}

func (m *RoutePolicy) Reset()                    { *m = RoutePolicy{} }
func (m *RoutePolicy) String() string            { return proto.CompactTextString(m) }
func (*RoutePolicy) ProtoMessage()               {}
func (*RoutePolicy) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *RoutePolicy) GetPath() string {
	if m != nil {
		return m.Path
	}
	return ""
}

func (m *RoutePolicy) GetQuery() map[string]string {
	if m != nil {
		return m.Query
	}
	return nil
}

func (m *RoutePolicy) GetActions() []string {
	if m != nil {
		return m.Actions
	}
	return nil
}

func (m *RoutePolicy) GetRequestAttributes() *RequestAttributes {
	if m != nil {
		return m.RequestAttributes
	}
	return nil
}

type RequestAttributes struct {
	Headers map[string]string `protobuf:"bytes,1,rep,name=headers" json:"headers,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	Cidr    string            `protobuf:"bytes,2,opt,name=cidr" json:"cidr,omitempty"`
	Host    string            `protobuf:"bytes,3,opt,name=host" json:"host,omitempty"`
}

func (m *RequestAttributes) Reset()                    { *m = RequestAttributes{} }
func (m *RequestAttributes) String() string            { return proto.CompactTextString(m) }
func (*RequestAttributes) ProtoMessage()               {}
func (*RequestAttributes) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *RequestAttributes) GetHeaders() map[string]string {
	if m != nil {
		return m.Headers
	}
	return nil
}

func (m *RequestAttributes) GetCidr() string {
	if m != nil {
		return m.Cidr
	}
	return ""
}

func (m *RequestAttributes) GetHost() string {
	if m != nil {
		return m.Host
	}
	return ""
}

type MethodPolicy struct {
	Service           string             `protobuf:"bytes,1,opt,name=service" json:"service,omitempty"`
	Methods           []string           `protobuf:"bytes,2,rep,name=methods" json:"methods,omitempty"`
	Parameters        map[string]string  `protobuf:"bytes,3,rep,name=parameters" json:"parameters,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	RequestAttributes *RequestAttributes `protobuf:"bytes,4,opt,name=requestAttributes" json:"requestAttributes,omitempty"`
}

func (m *MethodPolicy) Reset()                    { *m = MethodPolicy{} }
func (m *MethodPolicy) String() string            { return proto.CompactTextString(m) }
func (*MethodPolicy) ProtoMessage()               {}
func (*MethodPolicy) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *MethodPolicy) GetService() string {
	if m != nil {
		return m.Service
	}
	return ""
}

func (m *MethodPolicy) GetMethods() []string {
	if m != nil {
		return m.Methods
	}
	return nil
}

func (m *MethodPolicy) GetParameters() map[string]string {
	if m != nil {
		return m.Parameters
	}
	return nil
}

func (m *MethodPolicy) GetRequestAttributes() *RequestAttributes {
	if m != nil {
		return m.RequestAttributes
	}
	return nil
}

type IDQuery struct {
	Id   string `protobuf:"bytes,1,opt,name=id" json:"id,omitempty"`
	Name string `protobuf:"bytes,2,opt,name=name" json:"name,omitempty"`
}

func (m *IDQuery) Reset()                    { *m = IDQuery{} }
func (m *IDQuery) String() string            { return proto.CompactTextString(m) }
func (*IDQuery) ProtoMessage()               {}
func (*IDQuery) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *IDQuery) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *IDQuery) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type Query struct {
	EntityAttributes map[string]string `protobuf:"bytes,1,rep,name=entityAttributes" json:"entityAttributes,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
}

func (m *Query) Reset()                    { *m = Query{} }
func (m *Query) String() string            { return proto.CompactTextString(m) }
func (*Query) ProtoMessage()               {}
func (*Query) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

func (m *Query) GetEntityAttributes() map[string]string {
	if m != nil {
		return m.EntityAttributes
	}
	return nil
}

type Policies struct {
	Policies []*Policy `protobuf:"bytes,1,rep,name=policies" json:"policies,omitempty"`
}

func (m *Policies) Reset()                    { *m = Policies{} }
func (m *Policies) String() string            { return proto.CompactTextString(m) }
func (*Policies) ProtoMessage()               {}
func (*Policies) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

func (m *Policies) GetPolicies() []*Policy {
	if m != nil {
		return m.Policies
	}
	return nil
}

type Empty struct {
}

func (m *Empty) Reset()                    { *m = Empty{} }
func (m *Empty) String() string            { return proto.CompactTextString(m) }
func (*Empty) ProtoMessage()               {}
func (*Empty) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{7} }

func init() {
	proto.RegisterType((*Policy)(nil), "policy.Policy")
	proto.RegisterType((*RoutePolicy)(nil), "policy.RoutePolicy")
	proto.RegisterType((*RequestAttributes)(nil), "policy.RequestAttributes")
	proto.RegisterType((*MethodPolicy)(nil), "policy.MethodPolicy")
	proto.RegisterType((*IDQuery)(nil), "policy.IDQuery")
	proto.RegisterType((*Query)(nil), "policy.Query")
	proto.RegisterType((*Policies)(nil), "policy.Policies")
	proto.RegisterType((*Empty)(nil), "policy.Empty")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for PolicyService service

type PolicyServiceClient interface {
	GetPolicy(ctx context.Context, in *IDQuery, opts ...grpc.CallOption) (*Policy, error)
	ListPolicies(ctx context.Context, in *Query, opts ...grpc.CallOption) (*Policies, error)
	CreatePolicy(ctx context.Context, in *Policy, opts ...grpc.CallOption) (*Policy, error)
	UpdatePolicy(ctx context.Context, in *Policy, opts ...grpc.CallOption) (*Policy, error)
	PatchPolicy(ctx context.Context, in *Policy, opts ...grpc.CallOption) (*Policy, error)
	DeletePolicy(ctx context.Context, in *IDQuery, opts ...grpc.CallOption) (*Empty, error)
}

type policyServiceClient struct {
	cc *grpc.ClientConn
}

func NewPolicyServiceClient(cc *grpc.ClientConn) PolicyServiceClient {
	return &policyServiceClient{cc}
}

func (c *policyServiceClient) GetPolicy(ctx context.Context, in *IDQuery, opts ...grpc.CallOption) (*Policy, error) {
	out := new(Policy)
	err := grpc.Invoke(ctx, "/policy.PolicyService/GetPolicy", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *policyServiceClient) ListPolicies(ctx context.Context, in *Query, opts ...grpc.CallOption) (*Policies, error) {
	out := new(Policies)
	err := grpc.Invoke(ctx, "/policy.PolicyService/ListPolicies", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *policyServiceClient) CreatePolicy(ctx context.Context, in *Policy, opts ...grpc.CallOption) (*Policy, error) {
	out := new(Policy)
	err := grpc.Invoke(ctx, "/policy.PolicyService/CreatePolicy", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *policyServiceClient) UpdatePolicy(ctx context.Context, in *Policy, opts ...grpc.CallOption) (*Policy, error) {
	out := new(Policy)
	err := grpc.Invoke(ctx, "/policy.PolicyService/UpdatePolicy", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *policyServiceClient) PatchPolicy(ctx context.Context, in *Policy, opts ...grpc.CallOption) (*Policy, error) {
	out := new(Policy)
	err := grpc.Invoke(ctx, "/policy.PolicyService/PatchPolicy", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *policyServiceClient) DeletePolicy(ctx context.Context, in *IDQuery, opts ...grpc.CallOption) (*Empty, error) {
	out := new(Empty)
	err := grpc.Invoke(ctx, "/policy.PolicyService/DeletePolicy", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for PolicyService service

type PolicyServiceServer interface {
	GetPolicy(context.Context, *IDQuery) (*Policy, error)
	ListPolicies(context.Context, *Query) (*Policies, error)
	CreatePolicy(context.Context, *Policy) (*Policy, error)
	UpdatePolicy(context.Context, *Policy) (*Policy, error)
	PatchPolicy(context.Context, *Policy) (*Policy, error)
	DeletePolicy(context.Context, *IDQuery) (*Empty, error)
}

func RegisterPolicyServiceServer(s *grpc.Server, srv PolicyServiceServer) {
	s.RegisterService(&_PolicyService_serviceDesc, srv)
}

func _PolicyService_GetPolicy_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(IDQuery)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PolicyServiceServer).GetPolicy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/policy.PolicyService/GetPolicy",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PolicyServiceServer).GetPolicy(ctx, req.(*IDQuery))
	}
	return interceptor(ctx, in, info, handler)
}

func _PolicyService_ListPolicies_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Query)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PolicyServiceServer).ListPolicies(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/policy.PolicyService/ListPolicies",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PolicyServiceServer).ListPolicies(ctx, req.(*Query))
	}
	return interceptor(ctx, in, info, handler)
}

func _PolicyService_CreatePolicy_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Policy)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PolicyServiceServer).CreatePolicy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/policy.PolicyService/CreatePolicy",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PolicyServiceServer).CreatePolicy(ctx, req.(*Policy))
	}
	return interceptor(ctx, in, info, handler)
}

func _PolicyService_UpdatePolicy_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Policy)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PolicyServiceServer).UpdatePolicy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/policy.PolicyService/UpdatePolicy",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PolicyServiceServer).UpdatePolicy(ctx, req.(*Policy))
	}
	return interceptor(ctx, in, info, handler)
}

func _PolicyService_PatchPolicy_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Policy)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PolicyServiceServer).PatchPolicy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/policy.PolicyService/PatchPolicy",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PolicyServiceServer).PatchPolicy(ctx, req.(*Policy))
	}
	return interceptor(ctx, in, info, handler)
}

func _PolicyService_DeletePolicy_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(IDQuery)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PolicyServiceServer).DeletePolicy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/policy.PolicyService/DeletePolicy",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PolicyServiceServer).DeletePolicy(ctx, req.(*IDQuery))
	}
	return interceptor(ctx, in, info, handler)
}

var _PolicyService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "policy.PolicyService",
	HandlerType: (*PolicyServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetPolicy",
			Handler:    _PolicyService_GetPolicy_Handler,
		},
		{
			MethodName: "ListPolicies",
			Handler:    _PolicyService_ListPolicies_Handler,
		},
		{
			MethodName: "CreatePolicy",
			Handler:    _PolicyService_CreatePolicy_Handler,
		},
		{
			MethodName: "UpdatePolicy",
			Handler:    _PolicyService_UpdatePolicy_Handler,
		},
		{
			MethodName: "PatchPolicy",
			Handler:    _PolicyService_PatchPolicy_Handler,
		},
		{
			MethodName: "DeletePolicy",
			Handler:    _PolicyService_DeletePolicy_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/policy.proto",
}

func init() { proto.RegisterFile("api/policy.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 747 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x55, 0xdd, 0x6e, 0xd3, 0x4a,
	0x10, 0x96, 0xed, 0xfc, 0xd4, 0x13, 0xb7, 0x4d, 0xf7, 0xf4, 0x9c, 0xe3, 0x13, 0x1d, 0x55, 0x51,
	0x40, 0x34, 0x54, 0x22, 0x91, 0x02, 0x42, 0x55, 0x25, 0xa4, 0xd2, 0xa6, 0x14, 0x24, 0x10, 0xc1,
	0xc0, 0x0d, 0x77, 0x8e, 0xbd, 0x4d, 0x56, 0x4d, 0xb2, 0xae, 0xbd, 0xae, 0x14, 0x21, 0x6e, 0x78,
	0x02, 0x24, 0xae, 0x79, 0x07, 0x6e, 0xfb, 0x1c, 0xbc, 0x02, 0x8f, 0xc0, 0x03, 0x20, 0xcf, 0xae,
	0x53, 0x27, 0x0e, 0x52, 0x23, 0xf5, 0x6e, 0xd7, 0xfb, 0xed, 0x37, 0xdf, 0x7c, 0x33, 0x9e, 0x85,
	0xaa, 0x1b, 0xb0, 0x76, 0xc0, 0x47, 0xcc, 0x9b, 0xb6, 0x82, 0x90, 0x0b, 0x4e, 0x4a, 0x72, 0x57,
	0xfb, 0x7f, 0xc0, 0xf9, 0x60, 0x44, 0xdb, 0x09, 0xc0, 0x9d, 0x4c, 0xb8, 0x70, 0x05, 0xe3, 0x93,
	0x48, 0xa2, 0x1a, 0x57, 0x06, 0x94, 0x7a, 0x08, 0x24, 0x1b, 0xa0, 0x33, 0xdf, 0xd6, 0xea, 0x5a,
	0xd3, 0x74, 0x74, 0xe6, 0x93, 0x3a, 0x54, 0xbc, 0x90, 0xba, 0x82, 0xfa, 0xef, 0xd8, 0x98, 0xda,
	0x7a, 0x5d, 0x6b, 0x1a, 0x4e, 0xf6, 0x13, 0xd9, 0x01, 0x88, 0x03, 0xdf, 0x15, 0x14, 0x01, 0x06,
	0x02, 0x32, 0x5f, 0x08, 0x81, 0xc2, 0xc4, 0x1d, 0x53, 0xbb, 0x80, 0x9c, 0xb8, 0x26, 0x3d, 0xa8,
	0xd2, 0x89, 0x60, 0x62, 0xfa, 0x54, 0x88, 0x90, 0xf5, 0x63, 0x41, 0x23, 0xbb, 0x58, 0x37, 0x9a,
	0x95, 0xce, 0xdd, 0x96, 0xd2, 0x2f, 0xf5, 0xb4, 0x4e, 0x16, 0x60, 0x27, 0x13, 0x11, 0x4e, 0x9d,
	0xdc, 0x6d, 0xf2, 0x0f, 0x94, 0xe8, 0xd9, 0x19, 0xf5, 0x84, 0x5d, 0xc2, 0x38, 0x6a, 0x47, 0x4e,
	0x61, 0x2b, 0xa4, 0x17, 0x31, 0x8d, 0x44, 0x26, 0x54, 0xb9, 0xae, 0x35, 0x2b, 0x9d, 0xff, 0xd2,
	0x50, 0xce, 0x22, 0xc0, 0xc9, 0xdf, 0x21, 0xbb, 0x50, 0x18, 0x0a, 0x11, 0xd8, 0x6b, 0x28, 0xf3,
	0xaf, 0xd9, 0x5d, 0x1e, 0x0b, 0x2a, 0xb5, 0x3a, 0x08, 0x20, 0x4d, 0x28, 0x0c, 0xc2, 0xc0, 0xb3,
	0x4d, 0x04, 0x6e, 0xa7, 0xc0, 0x57, 0x54, 0x0c, 0xb9, 0x9f, 0x22, 0x13, 0x44, 0xed, 0x18, 0xfe,
	0x5e, 0x9a, 0x1e, 0xa9, 0x82, 0x71, 0x4e, 0xa7, 0xaa, 0x0a, 0xc9, 0x92, 0x6c, 0x43, 0xf1, 0xd2,
	0x1d, 0xc5, 0xb2, 0x00, 0xa6, 0x23, 0x37, 0x07, 0xfa, 0xbe, 0xd6, 0xf8, 0xa5, 0x41, 0x25, 0x23,
	0x22, 0xb1, 0x3b, 0x70, 0xc5, 0x50, 0x5d, 0xc6, 0x35, 0x79, 0x04, 0xc5, 0x8b, 0x98, 0x86, 0x53,
	0x5b, 0x47, 0x4d, 0x3b, 0x4b, 0xc4, 0xb7, 0xde, 0x24, 0x00, 0xe9, 0xae, 0x04, 0x13, 0x1b, 0xca,
	0xae, 0x87, 0x6d, 0x62, 0x1b, 0x75, 0xa3, 0x69, 0x3a, 0xe9, 0x76, 0xb9, 0xa9, 0x85, 0xd5, 0x4d,
	0xad, 0xed, 0x03, 0x5c, 0xc7, 0x5d, 0x29, 0xed, 0x2b, 0x0d, 0xb6, 0x72, 0x21, 0xc8, 0x21, 0x94,
	0x87, 0xd4, 0xf5, 0x69, 0x18, 0xd9, 0x1a, 0xa6, 0x7a, 0xef, 0x8f, 0x72, 0x5a, 0xcf, 0x25, 0x50,
	0xa6, 0x9c, 0x5e, 0x4b, 0xec, 0xf3, 0x98, 0x1f, 0xaa, 0x80, 0xb8, 0x4e, 0xbe, 0x0d, 0x79, 0x24,
	0xb0, 0xb7, 0x4d, 0x07, 0xd7, 0xb5, 0x03, 0xb0, 0xb2, 0x04, 0x2b, 0x69, 0xff, 0xa2, 0x83, 0x95,
	0x6d, 0x87, 0xc4, 0xe9, 0x88, 0x86, 0x97, 0xcc, 0xa3, 0x8a, 0x20, 0xdd, 0x26, 0x27, 0x63, 0x44,
	0x46, 0x58, 0x3b, 0xd3, 0x49, 0xb7, 0xa4, 0x0b, 0x10, 0xb8, 0xa1, 0x3b, 0xa6, 0x22, 0xc9, 0xd6,
	0x98, 0xff, 0x79, 0xb2, 0xec, 0xad, 0xde, 0x0c, 0x26, 0x73, 0xcd, 0xdc, 0xbb, 0xbd, 0x4a, 0x3e,
	0x81, 0xcd, 0x85, 0x38, 0x2b, 0x59, 0xf2, 0x00, 0xca, 0x2f, 0xba, 0xd8, 0x0a, 0xb9, 0x09, 0x94,
	0xce, 0x0f, 0xfd, 0x7a, 0x7e, 0x34, 0xbe, 0x69, 0x50, 0x94, 0xe8, 0xd7, 0x4b, 0x26, 0x89, 0x2c,
	0xfd, 0x9d, 0x54, 0x3f, 0x02, 0x6f, 0x3a, 0x48, 0x6e, 0xe7, 0xa7, 0x7c, 0x0c, 0x6b, 0x68, 0x3e,
	0xa3, 0x11, 0xd9, 0x83, 0xb5, 0x40, 0xad, 0x95, 0xb2, 0x8d, 0xf9, 0x19, 0xe7, 0xcc, 0xce, 0x1b,
	0x65, 0x28, 0x9e, 0x8c, 0x03, 0x31, 0xed, 0x7c, 0x37, 0x60, 0x5d, 0x9e, 0xbe, 0x55, 0x9d, 0x70,
	0x04, 0xe6, 0x29, 0x15, 0xaa, 0x61, 0x36, 0x53, 0x06, 0x65, 0x5a, 0x6d, 0x81, 0xb2, 0xb1, 0xfd,
	0xf9, 0xc7, 0xcf, 0xaf, 0xfa, 0x06, 0xb1, 0xd4, 0x73, 0xd0, 0xfe, 0xc8, 0xfc, 0x4f, 0xe4, 0x10,
	0xac, 0x97, 0x2c, 0x12, 0x33, 0x69, 0xeb, 0x73, 0x16, 0xd5, 0xaa, 0x73, 0x24, 0x89, 0x9e, 0x4d,
	0xa4, 0x31, 0x49, 0x59, 0xd1, 0x90, 0x23, 0xb0, 0x8e, 0x71, 0xf6, 0xa7, 0xcf, 0xc5, 0x7c, 0xdc,
	0x9c, 0x0e, 0x82, 0x04, 0x56, 0x23, 0x25, 0x38, 0xd0, 0xf6, 0xc8, 0x29, 0x58, 0xef, 0xf1, 0x79,
	0xb8, 0x21, 0xc7, 0xbf, 0xc8, 0xb1, 0x55, 0x9b, 0xcb, 0x25, 0x21, 0x7a, 0x06, 0x95, 0x9e, 0x2b,
	0xbc, 0xe1, 0x6a, 0x3c, 0x9d, 0x1c, 0x4f, 0x17, 0xac, 0x2e, 0x1d, 0xd1, 0x99, 0xa0, 0x9c, 0xbb,
	0x33, 0x9f, 0xb0, 0x38, 0xa9, 0xb9, 0x7b, 0x73, 0x44, 0x47, 0xf7, 0x3f, 0xec, 0x0e, 0x98, 0x18,
	0xc6, 0xfd, 0x96, 0xc7, 0xc7, 0xed, 0xf3, 0xb8, 0x4f, 0x3d, 0x1e, 0x06, 0x6d, 0x8f, 0x87, 0xee,
	0xa8, 0x1d, 0xf9, 0xe7, 0xed, 0x01, 0x57, 0xf8, 0x7e, 0x09, 0x9f, 0xdd, 0x87, 0xbf, 0x03, 0x00,
	0x00, 0xff, 0xff, 0x56, 0x33, 0x0d, 0x47, 0xb0, 0x07, 0x00, 0x00,
}