// Code generated by protoc-gen-go. DO NOT EDIT.
// source: api/billing.proto

/*
Package billing is a generated protocol buffer package.

It is generated from these files:
	api/billing.proto

It has these top-level messages:
	BillingRequest
	BillingResponse
	IDQuery
	ListQuery
	Account
	Accounts
	StripeAccount
	Empty
*/
package billing

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

type BillingRequest struct {
	RequestID string `protobuf:"bytes,1,opt,name=requestID" json:"requestID,omitempty"`
}

func (m *BillingRequest) Reset()                    { *m = BillingRequest{} }
func (m *BillingRequest) String() string            { return proto.CompactTextString(m) }
func (*BillingRequest) ProtoMessage()               {}
func (*BillingRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *BillingRequest) GetRequestID() string {
	if m != nil {
		return m.RequestID
	}
	return ""
}

type BillingResponse struct {
	Successful bool `protobuf:"varint,1,opt,name=successful" json:"successful,omitempty"`
}

func (m *BillingResponse) Reset()                    { *m = BillingResponse{} }
func (m *BillingResponse) String() string            { return proto.CompactTextString(m) }
func (*BillingResponse) ProtoMessage()               {}
func (*BillingResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *BillingResponse) GetSuccessful() bool {
	if m != nil {
		return m.Successful
	}
	return false
}

type IDQuery struct {
	Id   string `protobuf:"bytes,1,opt,name=id" json:"id,omitempty"`
	Name string `protobuf:"bytes,2,opt,name=name" json:"name,omitempty"`
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

func (m *IDQuery) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type ListQuery struct {
	EntityAttributes map[string]string `protobuf:"bytes,1,rep,name=entityAttributes" json:"entityAttributes,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
}

func (m *ListQuery) Reset()                    { *m = ListQuery{} }
func (m *ListQuery) String() string            { return proto.CompactTextString(m) }
func (*ListQuery) ProtoMessage()               {}
func (*ListQuery) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *ListQuery) GetEntityAttributes() map[string]string {
	if m != nil {
		return m.EntityAttributes
	}
	return nil
}

type Account struct {
	Id          string           `protobuf:"bytes,1,opt,name=id" json:"id,omitempty"`
	CreatedTime int64            `protobuf:"varint,2,opt,name=createdTime" json:"createdTime,omitempty"`
	UpdateTime  int64            `protobuf:"varint,3,opt,name=updateTime" json:"updateTime,omitempty"`
	Name        string           `protobuf:"bytes,4,opt,name=name" json:"name,omitempty"`
	Preferred   string           `protobuf:"bytes,5,opt,name=preferred" json:"preferred,omitempty"`
	Stripe      []*StripeAccount `protobuf:"bytes,6,rep,name=stripe" json:"stripe,omitempty"`
}

func (m *Account) Reset()                    { *m = Account{} }
func (m *Account) String() string            { return proto.CompactTextString(m) }
func (*Account) ProtoMessage()               {}
func (*Account) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *Account) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *Account) GetCreatedTime() int64 {
	if m != nil {
		return m.CreatedTime
	}
	return 0
}

func (m *Account) GetUpdateTime() int64 {
	if m != nil {
		return m.UpdateTime
	}
	return 0
}

func (m *Account) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Account) GetPreferred() string {
	if m != nil {
		return m.Preferred
	}
	return ""
}

func (m *Account) GetStripe() []*StripeAccount {
	if m != nil {
		return m.Stripe
	}
	return nil
}

type Accounts struct {
	Accounts []*Account `protobuf:"bytes,1,rep,name=accounts" json:"accounts,omitempty"`
}

func (m *Accounts) Reset()                    { *m = Accounts{} }
func (m *Accounts) String() string            { return proto.CompactTextString(m) }
func (*Accounts) ProtoMessage()               {}
func (*Accounts) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

func (m *Accounts) GetAccounts() []*Account {
	if m != nil {
		return m.Accounts
	}
	return nil
}

type StripeAccount struct {
	Id        string `protobuf:"bytes,1,opt,name=id" json:"id,omitempty"`
	Type      string `protobuf:"bytes,2,opt,name=type" json:"type,omitempty"`
	RecordPer int64  `protobuf:"varint,3,opt,name=recordPer" json:"recordPer,omitempty"`
	Verified  bool   `protobuf:"varint,4,opt,name=verified" json:"verified,omitempty"`
}

func (m *StripeAccount) Reset()                    { *m = StripeAccount{} }
func (m *StripeAccount) String() string            { return proto.CompactTextString(m) }
func (*StripeAccount) ProtoMessage()               {}
func (*StripeAccount) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

func (m *StripeAccount) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *StripeAccount) GetType() string {
	if m != nil {
		return m.Type
	}
	return ""
}

func (m *StripeAccount) GetRecordPer() int64 {
	if m != nil {
		return m.RecordPer
	}
	return 0
}

func (m *StripeAccount) GetVerified() bool {
	if m != nil {
		return m.Verified
	}
	return false
}

type Empty struct {
}

func (m *Empty) Reset()                    { *m = Empty{} }
func (m *Empty) String() string            { return proto.CompactTextString(m) }
func (*Empty) ProtoMessage()               {}
func (*Empty) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{7} }

func init() {
	proto.RegisterType((*BillingRequest)(nil), "billing.BillingRequest")
	proto.RegisterType((*BillingResponse)(nil), "billing.BillingResponse")
	proto.RegisterType((*IDQuery)(nil), "billing.IDQuery")
	proto.RegisterType((*ListQuery)(nil), "billing.ListQuery")
	proto.RegisterType((*Account)(nil), "billing.Account")
	proto.RegisterType((*Accounts)(nil), "billing.Accounts")
	proto.RegisterType((*StripeAccount)(nil), "billing.StripeAccount")
	proto.RegisterType((*Empty)(nil), "billing.Empty")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for BillingService service

type BillingServiceClient interface {
	Bill(ctx context.Context, in *BillingRequest, opts ...grpc.CallOption) (*BillingResponse, error)
	GetAccount(ctx context.Context, in *IDQuery, opts ...grpc.CallOption) (*Account, error)
	ListAccounts(ctx context.Context, in *ListQuery, opts ...grpc.CallOption) (*Accounts, error)
	CreateAccount(ctx context.Context, in *Account, opts ...grpc.CallOption) (*Account, error)
	UpdateAccount(ctx context.Context, in *Account, opts ...grpc.CallOption) (*Account, error)
	PatchAccount(ctx context.Context, in *Account, opts ...grpc.CallOption) (*Account, error)
	DeleteAccount(ctx context.Context, in *IDQuery, opts ...grpc.CallOption) (*Empty, error)
}

type billingServiceClient struct {
	cc *grpc.ClientConn
}

func NewBillingServiceClient(cc *grpc.ClientConn) BillingServiceClient {
	return &billingServiceClient{cc}
}

func (c *billingServiceClient) Bill(ctx context.Context, in *BillingRequest, opts ...grpc.CallOption) (*BillingResponse, error) {
	out := new(BillingResponse)
	err := grpc.Invoke(ctx, "/billing.BillingService/Bill", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *billingServiceClient) GetAccount(ctx context.Context, in *IDQuery, opts ...grpc.CallOption) (*Account, error) {
	out := new(Account)
	err := grpc.Invoke(ctx, "/billing.BillingService/GetAccount", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *billingServiceClient) ListAccounts(ctx context.Context, in *ListQuery, opts ...grpc.CallOption) (*Accounts, error) {
	out := new(Accounts)
	err := grpc.Invoke(ctx, "/billing.BillingService/ListAccounts", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *billingServiceClient) CreateAccount(ctx context.Context, in *Account, opts ...grpc.CallOption) (*Account, error) {
	out := new(Account)
	err := grpc.Invoke(ctx, "/billing.BillingService/CreateAccount", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *billingServiceClient) UpdateAccount(ctx context.Context, in *Account, opts ...grpc.CallOption) (*Account, error) {
	out := new(Account)
	err := grpc.Invoke(ctx, "/billing.BillingService/UpdateAccount", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *billingServiceClient) PatchAccount(ctx context.Context, in *Account, opts ...grpc.CallOption) (*Account, error) {
	out := new(Account)
	err := grpc.Invoke(ctx, "/billing.BillingService/PatchAccount", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *billingServiceClient) DeleteAccount(ctx context.Context, in *IDQuery, opts ...grpc.CallOption) (*Empty, error) {
	out := new(Empty)
	err := grpc.Invoke(ctx, "/billing.BillingService/DeleteAccount", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for BillingService service

type BillingServiceServer interface {
	Bill(context.Context, *BillingRequest) (*BillingResponse, error)
	GetAccount(context.Context, *IDQuery) (*Account, error)
	ListAccounts(context.Context, *ListQuery) (*Accounts, error)
	CreateAccount(context.Context, *Account) (*Account, error)
	UpdateAccount(context.Context, *Account) (*Account, error)
	PatchAccount(context.Context, *Account) (*Account, error)
	DeleteAccount(context.Context, *IDQuery) (*Empty, error)
}

func RegisterBillingServiceServer(s *grpc.Server, srv BillingServiceServer) {
	s.RegisterService(&_BillingService_serviceDesc, srv)
}

func _BillingService_Bill_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(BillingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BillingServiceServer).Bill(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/billing.BillingService/Bill",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BillingServiceServer).Bill(ctx, req.(*BillingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _BillingService_GetAccount_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(IDQuery)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BillingServiceServer).GetAccount(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/billing.BillingService/GetAccount",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BillingServiceServer).GetAccount(ctx, req.(*IDQuery))
	}
	return interceptor(ctx, in, info, handler)
}

func _BillingService_ListAccounts_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListQuery)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BillingServiceServer).ListAccounts(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/billing.BillingService/ListAccounts",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BillingServiceServer).ListAccounts(ctx, req.(*ListQuery))
	}
	return interceptor(ctx, in, info, handler)
}

func _BillingService_CreateAccount_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Account)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BillingServiceServer).CreateAccount(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/billing.BillingService/CreateAccount",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BillingServiceServer).CreateAccount(ctx, req.(*Account))
	}
	return interceptor(ctx, in, info, handler)
}

func _BillingService_UpdateAccount_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Account)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BillingServiceServer).UpdateAccount(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/billing.BillingService/UpdateAccount",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BillingServiceServer).UpdateAccount(ctx, req.(*Account))
	}
	return interceptor(ctx, in, info, handler)
}

func _BillingService_PatchAccount_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Account)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BillingServiceServer).PatchAccount(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/billing.BillingService/PatchAccount",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BillingServiceServer).PatchAccount(ctx, req.(*Account))
	}
	return interceptor(ctx, in, info, handler)
}

func _BillingService_DeleteAccount_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(IDQuery)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BillingServiceServer).DeleteAccount(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/billing.BillingService/DeleteAccount",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BillingServiceServer).DeleteAccount(ctx, req.(*IDQuery))
	}
	return interceptor(ctx, in, info, handler)
}

var _BillingService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "billing.BillingService",
	HandlerType: (*BillingServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Bill",
			Handler:    _BillingService_Bill_Handler,
		},
		{
			MethodName: "GetAccount",
			Handler:    _BillingService_GetAccount_Handler,
		},
		{
			MethodName: "ListAccounts",
			Handler:    _BillingService_ListAccounts_Handler,
		},
		{
			MethodName: "CreateAccount",
			Handler:    _BillingService_CreateAccount_Handler,
		},
		{
			MethodName: "UpdateAccount",
			Handler:    _BillingService_UpdateAccount_Handler,
		},
		{
			MethodName: "PatchAccount",
			Handler:    _BillingService_PatchAccount_Handler,
		},
		{
			MethodName: "DeleteAccount",
			Handler:    _BillingService_DeleteAccount_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/billing.proto",
}

func init() { proto.RegisterFile("api/billing.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 612 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x54, 0xcd, 0x4e, 0xdb, 0x4c,
	0x14, 0x95, 0xf3, 0x43, 0x92, 0x0b, 0x81, 0x30, 0xdf, 0x47, 0x6b, 0x59, 0xa8, 0x42, 0xb3, 0x8a,
	0x50, 0x1b, 0xab, 0x74, 0x83, 0xd8, 0xf1, 0x27, 0x40, 0xa5, 0x12, 0x35, 0x74, 0xd3, 0x9d, 0x63,
	0x5f, 0xc2, 0x08, 0xc7, 0xe3, 0xce, 0x8c, 0x91, 0xa2, 0xaa, 0x9b, 0xbe, 0x42, 0x9f, 0xa0, 0x9b,
	0xbe, 0x45, 0x9f, 0xa2, 0xaf, 0xd0, 0x07, 0xa9, 0x3c, 0x1e, 0x4f, 0x08, 0xce, 0xa6, 0xdd, 0xdd,
	0x39, 0x39, 0x73, 0x74, 0xcf, 0x99, 0x13, 0xc3, 0x66, 0x98, 0x31, 0x7f, 0xcc, 0x92, 0x84, 0xa5,
	0x93, 0x51, 0x26, 0xb8, 0xe2, 0xa4, 0x63, 0x8e, 0xde, 0xf6, 0x84, 0xf3, 0x49, 0x82, 0x7e, 0x41,
	0x09, 0xd3, 0x94, 0xab, 0x50, 0x31, 0x9e, 0xca, 0x92, 0x46, 0x47, 0xb0, 0x7e, 0x54, 0x12, 0x03,
	0xfc, 0x94, 0xa3, 0x54, 0x64, 0x1b, 0x7a, 0xa2, 0x1c, 0x2f, 0x4e, 0x5c, 0x67, 0xc7, 0x19, 0xf6,
	0x82, 0x39, 0x40, 0x5f, 0xc3, 0x86, 0xe5, 0xcb, 0x8c, 0xa7, 0x12, 0xc9, 0x0b, 0x00, 0x99, 0x47,
	0x11, 0x4a, 0x79, 0x9b, 0x27, 0xfa, 0x46, 0x37, 0x78, 0x84, 0xd0, 0x57, 0xd0, 0xb9, 0x38, 0x79,
	0x9f, 0xa3, 0x98, 0x91, 0x75, 0x68, 0xb0, 0xd8, 0x88, 0x36, 0x58, 0x4c, 0x08, 0xb4, 0xd2, 0x70,
	0x8a, 0x6e, 0x43, 0x23, 0x7a, 0xa6, 0x3f, 0x1c, 0xe8, 0x5d, 0x32, 0xa9, 0xca, 0x1b, 0x37, 0x30,
	0xc0, 0x54, 0x31, 0x35, 0x3b, 0x54, 0x4a, 0xb0, 0x71, 0xae, 0x50, 0xba, 0xce, 0x4e, 0x73, 0xb8,
	0xba, 0x37, 0x1c, 0x55, 0x86, 0x2d, 0x7b, 0x74, 0xfa, 0x84, 0x7a, 0x9a, 0x2a, 0x31, 0x0b, 0x6a,
	0x0a, 0xde, 0x31, 0x6c, 0x2d, 0xa5, 0x92, 0x01, 0x34, 0xef, 0x71, 0x66, 0x36, 0x2c, 0x46, 0xf2,
	0x3f, 0xb4, 0x1f, 0xc2, 0x24, 0xaf, 0x76, 0x2c, 0x0f, 0x07, 0x8d, 0x7d, 0x87, 0xfe, 0x74, 0xa0,
	0x73, 0x18, 0x45, 0x3c, 0x4f, 0x55, 0xcd, 0xd8, 0x0e, 0xac, 0x46, 0x02, 0x43, 0x85, 0xf1, 0x0d,
	0x33, 0xfe, 0x9a, 0xc1, 0x63, 0xa8, 0x48, 0x2d, 0xcf, 0xe2, 0x50, 0xa1, 0x26, 0x34, 0x35, 0xe1,
	0x11, 0x62, 0xa3, 0x69, 0xcd, 0xa3, 0x29, 0x9e, 0x26, 0x13, 0x78, 0x8b, 0x42, 0x60, 0xec, 0xb6,
	0xcb, 0xa7, 0xb1, 0x00, 0x19, 0xc1, 0x8a, 0x54, 0x82, 0x65, 0xe8, 0xae, 0xe8, 0x80, 0x9e, 0xd9,
	0x80, 0xae, 0x35, 0x6c, 0x76, 0x0d, 0x0c, 0x8b, 0xee, 0x43, 0xd7, 0x40, 0x92, 0xbc, 0x84, 0x6e,
	0x68, 0x66, 0x13, 0xef, 0xc0, 0xde, 0xae, 0xee, 0x59, 0x06, 0x9d, 0x42, 0x7f, 0x41, 0x72, 0xd9,
	0xbb, 0xaa, 0x59, 0x66, 0xdf, 0xb5, 0x98, 0xcb, 0x5e, 0x45, 0x5c, 0xc4, 0x57, 0x28, 0x8c, 0xdf,
	0x39, 0x40, 0x3c, 0xe8, 0x3e, 0xa0, 0x60, 0xb7, 0x0c, 0x63, 0x6d, 0xb9, 0x1b, 0xd8, 0x33, 0xed,
	0x40, 0xfb, 0x74, 0x9a, 0xa9, 0xd9, 0xde, 0xf7, 0x96, 0x6d, 0xeb, 0x35, 0x8a, 0x07, 0x16, 0x21,
	0x79, 0x0b, 0xad, 0x02, 0x21, 0xcf, 0xed, 0xba, 0x8b, 0x75, 0xf6, 0xdc, 0xfa, 0x0f, 0x65, 0x6f,
	0xe9, 0xe0, 0xeb, 0xaf, 0xdf, 0xdf, 0x1a, 0x40, 0xdb, 0xfa, 0x9f, 0x73, 0xe0, 0xec, 0x92, 0x33,
	0x80, 0x33, 0x54, 0x95, 0xa9, 0x79, 0x02, 0xa6, 0xbe, 0x5e, 0x2d, 0x13, 0xba, 0xa5, 0x35, 0x36,
	0x48, 0xdf, 0x37, 0xe1, 0xf8, 0x9f, 0x59, 0xfc, 0x85, 0x9c, 0xc3, 0x5a, 0x51, 0x4a, 0x1b, 0x2f,
	0xa9, 0x77, 0xd5, 0xdb, 0x7c, 0x2a, 0x26, 0xe9, 0xa6, 0x56, 0x5b, 0x25, 0xbd, 0x4a, 0x4d, 0x92,
	0x73, 0xe8, 0x1f, 0xeb, 0xd6, 0xd4, 0xb7, 0x32, 0xc8, 0x92, 0xad, 0xfe, 0xd3, 0x3a, 0x7d, 0xda,
	0xad, 0x74, 0x0a, 0x73, 0xef, 0xa0, 0xff, 0x41, 0xd7, 0xeb, 0x6f, 0x94, 0x5c, 0xad, 0x44, 0xbc,
	0x45, 0x7f, 0x85, 0xdc, 0x25, 0xac, 0x5d, 0x85, 0x2a, 0xba, 0xfb, 0x07, 0xb5, 0xbd, 0xba, 0xda,
	0x39, 0xf4, 0x4f, 0x30, 0xc1, 0x65, 0xcb, 0x55, 0xe1, 0xaf, 0x5b, 0x44, 0x97, 0xa1, 0x8a, 0x7e,
	0x77, 0x51, 0xec, 0x68, 0xf7, 0xe3, 0x70, 0xc2, 0xd4, 0x5d, 0x3e, 0x1e, 0x45, 0x7c, 0xea, 0xdf,
	0xe7, 0xe3, 0xa2, 0x62, 0x99, 0x1f, 0x71, 0x11, 0x26, 0xbe, 0x8c, 0xef, 0xfd, 0x09, 0xaf, 0xbe,
	0x94, 0xe3, 0x15, 0xfd, 0x0d, 0x7c, 0xf3, 0x27, 0x00, 0x00, 0xff, 0xff, 0xc3, 0x73, 0x3a, 0x58,
	0x3f, 0x05, 0x00, 0x00,
}
