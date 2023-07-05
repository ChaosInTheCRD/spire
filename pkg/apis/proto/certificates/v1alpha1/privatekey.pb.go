// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.23.3
// source: v1alpha1/privatekey.proto

package v1alpha1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// PrivateKeyAlgorithm is the type of public key cryptography algorithm to be
// used to generate and sign X.509 certificatess.
type PrivateKeyAlgorithm int32

const (
	// PRIVATE_KEY_ALGORITHM_RSA is the Rivest–Shamir–Adleman public key
	// algorithm.
	// https://en.wikipedia.org/wiki/RSA_(cryptosystem)
	PrivateKeyAlgorithm_PRIVATE_KEY_ALGORITHM_RSA PrivateKeyAlgorithm = 0
	// PRIVATE_KEY_ALGORITHM_ECDS is the Elliptic Curve Digital Signature
	// Algorithm.
	// https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Sign/ature_Algorithm
	PrivateKeyAlgorithm_PRIVATE_KEY_ALGORITHM_ECDSA PrivateKeyAlgorithm = 1
	// PRIVATE_KEY_ALGORITHM_ED25519 is a EdDSA using Curve25519
	// https://en.wikipedia.org/wiki/EdDSA#Ed25519
	PrivateKeyAlgorithm_PRIVATE_KEY_ALGORITHM_ED25519 PrivateKeyAlgorithm = 2
)

// Enum value maps for PrivateKeyAlgorithm.
var (
	PrivateKeyAlgorithm_name = map[int32]string{
		0: "PRIVATE_KEY_ALGORITHM_RSA",
		1: "PRIVATE_KEY_ALGORITHM_ECDSA",
		2: "PRIVATE_KEY_ALGORITHM_ED25519",
	}
	PrivateKeyAlgorithm_value = map[string]int32{
		"PRIVATE_KEY_ALGORITHM_RSA":     0,
		"PRIVATE_KEY_ALGORITHM_ECDSA":   1,
		"PRIVATE_KEY_ALGORITHM_ED25519": 2,
	}
)

func (x PrivateKeyAlgorithm) Enum() *PrivateKeyAlgorithm {
	p := new(PrivateKeyAlgorithm)
	*p = x
	return p
}

func (x PrivateKeyAlgorithm) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (PrivateKeyAlgorithm) Descriptor() protoreflect.EnumDescriptor {
	return file_v1alpha1_privatekey_proto_enumTypes[0].Descriptor()
}

func (PrivateKeyAlgorithm) Type() protoreflect.EnumType {
	return &file_v1alpha1_privatekey_proto_enumTypes[0]
}

func (x PrivateKeyAlgorithm) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use PrivateKeyAlgorithm.Descriptor instead.
func (PrivateKeyAlgorithm) EnumDescriptor() ([]byte, []int) {
	return file_v1alpha1_privatekey_proto_rawDescGZIP(), []int{0}
}

// PrivateKeyRequest is a request by the client for the server to generate a
// private key. The client can request the algorithm used to generate the key,
// and the size of the key if relevant.
type PrivateKeyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// algorithm is the type of public key cryptography algorithm to be used to
	// generate the private key.
	Algorithm PrivateKeyAlgorithm `protobuf:"varint,1,opt,name=algorithm,proto3,enum=certificates.v1alpha1.PrivateKeyAlgorithm" json:"algorithm,omitempty"`
	// Size is an optional field to request a specific "size" of the private key.
	// If algorithm is specified as below and `size` is not provided:
	// - PRIVATE_KEY_ALGORITHM_RSA: size will default to 2048.
	// - PRIVATE_KEY_ALGORITHM_ECDSA: size will default to 256.
	// - PRIVATE_KEY_ALGORITHM_ED25519: size is not supported.
	// If size is defined, then it must be:
	// - PRIVATE_KEY_ALGORITHM_RSA: 2048 <= size <= 4096
	// - PRIVATE_KEY_ALGORITHM_ECDSA: 256, 384, 521
	// - PRIVATE_KEY_ALGORITHM_ED25519: rejected when defined.
	Size *uint64 `protobuf:"varint,2,opt,name=size,proto3,oneof" json:"size,omitempty"`
}

func (x *PrivateKeyRequest) Reset() {
	*x = PrivateKeyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_v1alpha1_privatekey_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PrivateKeyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PrivateKeyRequest) ProtoMessage() {}

func (x *PrivateKeyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_v1alpha1_privatekey_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PrivateKeyRequest.ProtoReflect.Descriptor instead.
func (*PrivateKeyRequest) Descriptor() ([]byte, []int) {
	return file_v1alpha1_privatekey_proto_rawDescGZIP(), []int{0}
}

func (x *PrivateKeyRequest) GetAlgorithm() PrivateKeyAlgorithm {
	if x != nil {
		return x.Algorithm
	}
	return PrivateKeyAlgorithm_PRIVATE_KEY_ALGORITHM_RSA
}

func (x *PrivateKeyRequest) GetSize() uint64 {
	if x != nil && x.Size != nil {
		return *x.Size
	}
	return 0
}

var File_v1alpha1_privatekey_proto protoreflect.FileDescriptor

var file_v1alpha1_privatekey_proto_rawDesc = []byte{
	0x0a, 0x19, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2f, 0x70, 0x72, 0x69, 0x76, 0x61,
	0x74, 0x65, 0x6b, 0x65, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x15, 0x63, 0x65, 0x72,
	0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68,
	0x61, 0x31, 0x22, 0x7f, 0x0a, 0x11, 0x50, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x48, 0x0a, 0x09, 0x61, 0x6c, 0x67, 0x6f, 0x72,
	0x69, 0x74, 0x68, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x2a, 0x2e, 0x63, 0x65, 0x72,
	0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68,
	0x61, 0x31, 0x2e, 0x50, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x41, 0x6c, 0x67,
	0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x52, 0x09, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68,
	0x6d, 0x12, 0x17, 0x0a, 0x04, 0x73, 0x69, 0x7a, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x48,
	0x00, 0x52, 0x04, 0x73, 0x69, 0x7a, 0x65, 0x88, 0x01, 0x01, 0x42, 0x07, 0x0a, 0x05, 0x5f, 0x73,
	0x69, 0x7a, 0x65, 0x2a, 0x78, 0x0a, 0x13, 0x50, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x4b, 0x65,
	0x79, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x12, 0x1d, 0x0a, 0x19, 0x50, 0x52,
	0x49, 0x56, 0x41, 0x54, 0x45, 0x5f, 0x4b, 0x45, 0x59, 0x5f, 0x41, 0x4c, 0x47, 0x4f, 0x52, 0x49,
	0x54, 0x48, 0x4d, 0x5f, 0x52, 0x53, 0x41, 0x10, 0x00, 0x12, 0x1f, 0x0a, 0x1b, 0x50, 0x52, 0x49,
	0x56, 0x41, 0x54, 0x45, 0x5f, 0x4b, 0x45, 0x59, 0x5f, 0x41, 0x4c, 0x47, 0x4f, 0x52, 0x49, 0x54,
	0x48, 0x4d, 0x5f, 0x45, 0x43, 0x44, 0x53, 0x41, 0x10, 0x01, 0x12, 0x21, 0x0a, 0x1d, 0x50, 0x52,
	0x49, 0x56, 0x41, 0x54, 0x45, 0x5f, 0x4b, 0x45, 0x59, 0x5f, 0x41, 0x4c, 0x47, 0x4f, 0x52, 0x49,
	0x54, 0x48, 0x4d, 0x5f, 0x45, 0x44, 0x32, 0x35, 0x35, 0x31, 0x39, 0x10, 0x02, 0x42, 0x72, 0x5a,
	0x70, 0x67, 0x69, 0x74, 0x6c, 0x61, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x76, 0x65, 0x6e, 0x61,
	0x66, 0x69, 0x2f, 0x76, 0x61, 0x61, 0x73, 0x2f, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x74, 0x6c, 0x73, 0x2d, 0x70, 0x72, 0x6f, 0x74, 0x65, 0x63, 0x74,
	0x2f, 0x64, 0x6d, 0x69, 0x2f, 0x63, 0x6c, 0x69, 0x2f, 0x66, 0x69, 0x72, 0x65, 0x66, 0x6c, 0x79,
	0x2d, 0x63, 0x61, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x61, 0x70, 0x69, 0x73, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2f, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x2f,
	0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x3b, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61,
	0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_v1alpha1_privatekey_proto_rawDescOnce sync.Once
	file_v1alpha1_privatekey_proto_rawDescData = file_v1alpha1_privatekey_proto_rawDesc
)

func file_v1alpha1_privatekey_proto_rawDescGZIP() []byte {
	file_v1alpha1_privatekey_proto_rawDescOnce.Do(func() {
		file_v1alpha1_privatekey_proto_rawDescData = protoimpl.X.CompressGZIP(file_v1alpha1_privatekey_proto_rawDescData)
	})
	return file_v1alpha1_privatekey_proto_rawDescData
}

var file_v1alpha1_privatekey_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_v1alpha1_privatekey_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_v1alpha1_privatekey_proto_goTypes = []interface{}{
	(PrivateKeyAlgorithm)(0),  // 0: certificates.v1alpha1.PrivateKeyAlgorithm
	(*PrivateKeyRequest)(nil), // 1: certificates.v1alpha1.PrivateKeyRequest
}
var file_v1alpha1_privatekey_proto_depIdxs = []int32{
	0, // 0: certificates.v1alpha1.PrivateKeyRequest.algorithm:type_name -> certificates.v1alpha1.PrivateKeyAlgorithm
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_v1alpha1_privatekey_proto_init() }
func file_v1alpha1_privatekey_proto_init() {
	if File_v1alpha1_privatekey_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_v1alpha1_privatekey_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PrivateKeyRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_v1alpha1_privatekey_proto_msgTypes[0].OneofWrappers = []interface{}{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_v1alpha1_privatekey_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_v1alpha1_privatekey_proto_goTypes,
		DependencyIndexes: file_v1alpha1_privatekey_proto_depIdxs,
		EnumInfos:         file_v1alpha1_privatekey_proto_enumTypes,
		MessageInfos:      file_v1alpha1_privatekey_proto_msgTypes,
	}.Build()
	File_v1alpha1_privatekey_proto = out.File
	file_v1alpha1_privatekey_proto_rawDesc = nil
	file_v1alpha1_privatekey_proto_goTypes = nil
	file_v1alpha1_privatekey_proto_depIdxs = nil
}
