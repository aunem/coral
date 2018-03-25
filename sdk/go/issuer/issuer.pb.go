// Code generated by protoc-gen-go. DO NOT EDIT.
// source: api/issuer.proto

/*
Package issuer is a generated protocol buffer package.

It is generated from these files:
	api/issuer.proto

It has these top-level messages:
	Issuer
	Issuers
	IDQuery
	Query
	Empty
*/
package issuer

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

type Issuer struct {
	Id           string `protobuf:"bytes,1,opt,name=id" json:"id,omitempty"`
	CreatedTime  int64  `protobuf:"varint,2,opt,name=createdTime" json:"createdTime,omitempty"`
	UpdateTime   int64  `protobuf:"varint,3,opt,name=updateTime" json:"updateTime,omitempty"`
	Name         string `protobuf:"bytes,4,opt,name=name" json:"name,omitempty"`
	Issuer       string `protobuf:"bytes,5,opt,name=issuer" json:"issuer,omitempty"`
	JwksUri      string `protobuf:"bytes,6,opt,name=jwksUri" json:"jwksUri,omitempty"`
	IssuerClaim  string `protobuf:"bytes,7,opt,name=issuerClaim" json:"issuerClaim,omitempty"`
	SubjectClaim string `protobuf:"bytes,8,opt,name=subjectClaim" json:"subjectClaim,omitempty"`
	ExpiresClaim string `protobuf:"bytes,9,opt,name=expiresClaim" json:"expiresClaim,omitempty"`
}

func (m *Issuer) Reset()                    { *m = Issuer{} }
func (m *Issuer) String() string            { return proto.CompactTextString(m) }
func (*Issuer) ProtoMessage()               {}
func (*Issuer) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Issuer) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *Issuer) GetCreatedTime() int64 {
	if m != nil {
		return m.CreatedTime
	}
	return 0
}

func (m *Issuer) GetUpdateTime() int64 {
	if m != nil {
		return m.UpdateTime
	}
	return 0
}

func (m *Issuer) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Issuer) GetIssuer() string {
	if m != nil {
		return m.Issuer
	}
	return ""
}

func (m *Issuer) GetJwksUri() string {
	if m != nil {
		return m.JwksUri
	}
	return ""
}

func (m *Issuer) GetIssuerClaim() string {
	if m != nil {
		return m.IssuerClaim
	}
	return ""
}

func (m *Issuer) GetSubjectClaim() string {
	if m != nil {
		return m.SubjectClaim
	}
	return ""
}

func (m *Issuer) GetExpiresClaim() string {
	if m != nil {
		return m.ExpiresClaim
	}
	return ""
}

type Issuers struct {
	Issuers []*Issuer `protobuf:"bytes,1,rep,name=issuers" json:"issuers,omitempty"`
}

func (m *Issuers) Reset()                    { *m = Issuers{} }
func (m *Issuers) String() string            { return proto.CompactTextString(m) }
func (*Issuers) ProtoMessage()               {}
func (*Issuers) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *Issuers) GetIssuers() []*Issuer {
	if m != nil {
		return m.Issuers
	}
	return nil
}

type IDQuery struct {
	Id string `protobuf:"bytes,1,opt,name=id" json:"id,omitempty"`
}

func (m *IDQuery) Reset()                    { *m = IDQuery{} }
func (m *IDQuery) String() string            { return proto.CompactTextString(m) }
func (*IDQuery) ProtoMessage()               {}
func (*IDQuery) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *IDQuery) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

type Query struct {
	Name   string `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
	Issuer string `protobuf:"bytes,2,opt,name=issuer" json:"issuer,omitempty"`
}

func (m *Query) Reset()                    { *m = Query{} }
func (m *Query) String() string            { return proto.CompactTextString(m) }
func (*Query) ProtoMessage()               {}
func (*Query) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *Query) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Query) GetIssuer() string {
	if m != nil {
		return m.Issuer
	}
	return ""
}

type Empty struct {
}

func (m *Empty) Reset()                    { *m = Empty{} }
func (m *Empty) String() string            { return proto.CompactTextString(m) }
func (*Empty) ProtoMessage()               {}
func (*Empty) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func init() {
	proto.RegisterType((*Issuer)(nil), "issuer.Issuer")
	proto.RegisterType((*Issuers)(nil), "issuer.Issuers")
	proto.RegisterType((*IDQuery)(nil), "issuer.IDQuery")
	proto.RegisterType((*Query)(nil), "issuer.Query")
	proto.RegisterType((*Empty)(nil), "issuer.Empty")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for IssuerService service

type IssuerServiceClient interface {
	GetIssuer(ctx context.Context, in *IDQuery, opts ...grpc.CallOption) (*Issuer, error)
	ListIssuers(ctx context.Context, in *Query, opts ...grpc.CallOption) (*Issuers, error)
	CreateIssuer(ctx context.Context, in *Issuer, opts ...grpc.CallOption) (*Issuer, error)
	UpdateIssuer(ctx context.Context, in *Issuer, opts ...grpc.CallOption) (*Issuer, error)
	PatchIssuer(ctx context.Context, in *Issuer, opts ...grpc.CallOption) (*Issuer, error)
	DeleteIssuer(ctx context.Context, in *IDQuery, opts ...grpc.CallOption) (*Empty, error)
}

type issuerServiceClient struct {
	cc *grpc.ClientConn
}

func NewIssuerServiceClient(cc *grpc.ClientConn) IssuerServiceClient {
	return &issuerServiceClient{cc}
}

func (c *issuerServiceClient) GetIssuer(ctx context.Context, in *IDQuery, opts ...grpc.CallOption) (*Issuer, error) {
	out := new(Issuer)
	err := grpc.Invoke(ctx, "/issuer.IssuerService/GetIssuer", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *issuerServiceClient) ListIssuers(ctx context.Context, in *Query, opts ...grpc.CallOption) (*Issuers, error) {
	out := new(Issuers)
	err := grpc.Invoke(ctx, "/issuer.IssuerService/ListIssuers", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *issuerServiceClient) CreateIssuer(ctx context.Context, in *Issuer, opts ...grpc.CallOption) (*Issuer, error) {
	out := new(Issuer)
	err := grpc.Invoke(ctx, "/issuer.IssuerService/CreateIssuer", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *issuerServiceClient) UpdateIssuer(ctx context.Context, in *Issuer, opts ...grpc.CallOption) (*Issuer, error) {
	out := new(Issuer)
	err := grpc.Invoke(ctx, "/issuer.IssuerService/UpdateIssuer", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *issuerServiceClient) PatchIssuer(ctx context.Context, in *Issuer, opts ...grpc.CallOption) (*Issuer, error) {
	out := new(Issuer)
	err := grpc.Invoke(ctx, "/issuer.IssuerService/PatchIssuer", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *issuerServiceClient) DeleteIssuer(ctx context.Context, in *IDQuery, opts ...grpc.CallOption) (*Empty, error) {
	out := new(Empty)
	err := grpc.Invoke(ctx, "/issuer.IssuerService/DeleteIssuer", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for IssuerService service

type IssuerServiceServer interface {
	GetIssuer(context.Context, *IDQuery) (*Issuer, error)
	ListIssuers(context.Context, *Query) (*Issuers, error)
	CreateIssuer(context.Context, *Issuer) (*Issuer, error)
	UpdateIssuer(context.Context, *Issuer) (*Issuer, error)
	PatchIssuer(context.Context, *Issuer) (*Issuer, error)
	DeleteIssuer(context.Context, *IDQuery) (*Empty, error)
}

func RegisterIssuerServiceServer(s *grpc.Server, srv IssuerServiceServer) {
	s.RegisterService(&_IssuerService_serviceDesc, srv)
}

func _IssuerService_GetIssuer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(IDQuery)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IssuerServiceServer).GetIssuer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/issuer.IssuerService/GetIssuer",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IssuerServiceServer).GetIssuer(ctx, req.(*IDQuery))
	}
	return interceptor(ctx, in, info, handler)
}

func _IssuerService_ListIssuers_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Query)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IssuerServiceServer).ListIssuers(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/issuer.IssuerService/ListIssuers",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IssuerServiceServer).ListIssuers(ctx, req.(*Query))
	}
	return interceptor(ctx, in, info, handler)
}

func _IssuerService_CreateIssuer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Issuer)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IssuerServiceServer).CreateIssuer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/issuer.IssuerService/CreateIssuer",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IssuerServiceServer).CreateIssuer(ctx, req.(*Issuer))
	}
	return interceptor(ctx, in, info, handler)
}

func _IssuerService_UpdateIssuer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Issuer)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IssuerServiceServer).UpdateIssuer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/issuer.IssuerService/UpdateIssuer",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IssuerServiceServer).UpdateIssuer(ctx, req.(*Issuer))
	}
	return interceptor(ctx, in, info, handler)
}

func _IssuerService_PatchIssuer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Issuer)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IssuerServiceServer).PatchIssuer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/issuer.IssuerService/PatchIssuer",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IssuerServiceServer).PatchIssuer(ctx, req.(*Issuer))
	}
	return interceptor(ctx, in, info, handler)
}

func _IssuerService_DeleteIssuer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(IDQuery)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IssuerServiceServer).DeleteIssuer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/issuer.IssuerService/DeleteIssuer",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IssuerServiceServer).DeleteIssuer(ctx, req.(*IDQuery))
	}
	return interceptor(ctx, in, info, handler)
}

var _IssuerService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "issuer.IssuerService",
	HandlerType: (*IssuerServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetIssuer",
			Handler:    _IssuerService_GetIssuer_Handler,
		},
		{
			MethodName: "ListIssuers",
			Handler:    _IssuerService_ListIssuers_Handler,
		},
		{
			MethodName: "CreateIssuer",
			Handler:    _IssuerService_CreateIssuer_Handler,
		},
		{
			MethodName: "UpdateIssuer",
			Handler:    _IssuerService_UpdateIssuer_Handler,
		},
		{
			MethodName: "PatchIssuer",
			Handler:    _IssuerService_PatchIssuer_Handler,
		},
		{
			MethodName: "DeleteIssuer",
			Handler:    _IssuerService_DeleteIssuer_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/issuer.proto",
}

func init() { proto.RegisterFile("api/issuer.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 470 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x93, 0xc1, 0x8e, 0xd3, 0x30,
	0x10, 0x86, 0x95, 0x74, 0xb7, 0xa1, 0xd3, 0x6c, 0x0b, 0x23, 0x04, 0xa1, 0x42, 0xa8, 0xf2, 0x85,
	0xb2, 0x87, 0x46, 0x6a, 0x6f, 0x1c, 0x38, 0x74, 0x0b, 0xab, 0x95, 0x38, 0x40, 0x61, 0x2f, 0xdc,
	0xdc, 0x64, 0xd4, 0xf5, 0xb6, 0xa9, 0x23, 0xdb, 0x01, 0x56, 0x88, 0x0b, 0x47, 0xae, 0xbc, 0x07,
	0x2f, 0xc3, 0x2b, 0xf0, 0x20, 0xa8, 0x76, 0x52, 0x25, 0x5b, 0x0e, 0x70, 0x8b, 0x67, 0x7e, 0x7f,
	0xfe, 0xfd, 0x7b, 0x02, 0x77, 0x79, 0x2e, 0x62, 0xa1, 0x75, 0x41, 0x6a, 0x9c, 0x2b, 0x69, 0x24,
	0xb6, 0xdd, 0x6a, 0xf0, 0x78, 0x25, 0xe5, 0x6a, 0x43, 0xf1, 0x4e, 0xc0, 0xb7, 0x5b, 0x69, 0xb8,
	0x11, 0x72, 0xab, 0x9d, 0x8a, 0x7d, 0xf7, 0xa1, 0x7d, 0x61, 0x85, 0xd8, 0x03, 0x5f, 0xa4, 0x91,
	0x37, 0xf4, 0x46, 0x9d, 0x85, 0x2f, 0x52, 0x1c, 0x42, 0x37, 0x51, 0xc4, 0x0d, 0xa5, 0xef, 0x45,
	0x46, 0x91, 0x3f, 0xf4, 0x46, 0xad, 0x45, 0xbd, 0x84, 0x4f, 0x00, 0x8a, 0x3c, 0xe5, 0x86, 0xac,
	0xa0, 0x65, 0x05, 0xb5, 0x0a, 0x22, 0x1c, 0x6d, 0x79, 0x46, 0xd1, 0x91, 0x65, 0xda, 0x6f, 0x7c,
	0x00, 0xa5, 0xb1, 0xe8, 0xd8, 0x56, 0xcb, 0x15, 0x46, 0x10, 0x5c, 0x7f, 0x5a, 0xeb, 0x4b, 0x25,
	0xa2, 0xb6, 0x6d, 0x54, 0xcb, 0x9d, 0x0f, 0xa7, 0x39, 0xdb, 0x70, 0x91, 0x45, 0x81, 0xed, 0xd6,
	0x4b, 0xc8, 0x20, 0xd4, 0xc5, 0xf2, 0x9a, 0x12, 0xe3, 0x24, 0x77, 0xac, 0xa4, 0x51, 0xdb, 0x69,
	0xe8, 0x73, 0x2e, 0x14, 0x69, 0xa7, 0xe9, 0x38, 0x4d, 0xbd, 0xc6, 0xa6, 0x10, 0xb8, 0x2c, 0x34,
	0x8e, 0x20, 0x70, 0x27, 0xe8, 0xc8, 0x1b, 0xb6, 0x46, 0xdd, 0x49, 0x6f, 0x5c, 0xa6, 0xeb, 0x14,
	0x8b, 0xaa, 0xcd, 0x1e, 0x41, 0x70, 0x31, 0x7f, 0x5b, 0x90, 0xba, 0xb9, 0x9d, 0x20, 0x9b, 0xc2,
	0xb1, 0x6b, 0x54, 0x41, 0x78, 0x7f, 0x0d, 0xc2, 0xaf, 0x07, 0xc1, 0x02, 0x38, 0x7e, 0x99, 0xe5,
	0xe6, 0x66, 0xf2, 0xb3, 0x05, 0x27, 0xee, 0xb0, 0x77, 0xa4, 0x3e, 0x8a, 0x84, 0x70, 0x06, 0x9d,
	0x73, 0x32, 0xe5, 0x73, 0xf5, 0xf7, 0x86, 0xdc, 0xe9, 0x83, 0x5b, 0x0e, 0xd9, 0xfd, 0x6f, 0xbf,
	0x7e, 0xff, 0xf0, 0x7b, 0x18, 0x96, 0x73, 0x11, 0x7f, 0x11, 0xe9, 0x57, 0x7c, 0x01, 0xdd, 0xd7,
	0x42, 0x9b, 0xea, 0x9e, 0x27, 0xd5, 0x26, 0xc7, 0xe8, 0x37, 0x19, 0x9a, 0xf5, 0x2d, 0xa4, 0x83,
	0x41, 0x09, 0xc1, 0x19, 0x84, 0x67, 0x76, 0x04, 0xaa, 0xa9, 0x69, 0xee, 0x38, 0x70, 0x81, 0x16,
	0x10, 0xb2, 0x0a, 0xf0, 0xdc, 0x3b, 0xc5, 0x73, 0x08, 0x2f, 0xed, 0x94, 0xfc, 0x23, 0xe3, 0xa1,
	0x65, 0xdc, 0x1b, 0x34, 0x6e, 0xb2, 0x03, 0xbd, 0x82, 0xee, 0x1b, 0x6e, 0x92, 0xab, 0xff, 0xe3,
	0x4c, 0x0e, 0x38, 0x73, 0x08, 0xe7, 0xb4, 0xa1, 0xbd, 0xa1, 0x83, 0x6c, 0xf7, 0x31, 0xd9, 0xa7,
	0xa9, 0xa2, 0x3d, 0x6d, 0x80, 0x66, 0xcf, 0x3e, 0x3c, 0x5d, 0x09, 0x73, 0x55, 0x2c, 0xc7, 0x89,
	0xcc, 0xe2, 0x75, 0xb1, 0xa4, 0x44, 0xaa, 0x3c, 0x4e, 0xa4, 0xe2, 0x9b, 0x58, 0xa7, 0xeb, 0x78,
	0x25, 0x4b, 0xfd, 0xb2, 0x6d, 0xff, 0xbe, 0xe9, 0x9f, 0x00, 0x00, 0x00, 0xff, 0xff, 0xf3, 0x25,
	0x5d, 0xe5, 0xb7, 0x03, 0x00, 0x00,
}
