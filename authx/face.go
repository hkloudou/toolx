package authx

//ITokenBaseEnDecoder face
type ITokenBaseEnDecoder interface {
	Encode(userNo uint64, clientID string) ([]byte, error)
	Decode(b []byte) (*TokenBase, error)
}

type ISigner interface {
	// Sign([]byte) string
	Sign(data []byte) (string, error)
	VerifySign(data []byte, signed string) error
}
