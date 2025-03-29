package protocol

// Implement the unmarshal
type ProtoType interface {
	Unmarshal([]byte) error
}

type Trans interface {
	TransmissionSDK(ProtoType, bool) error
}

type Config interface {
	GetName() string
	GetType() string
	GetVersion() string
	GetSha256() string
	GetSignature() string
	GetDownloadUrls() []string
	GetDetail() string
}

type PoolGet = func() ProtoType
