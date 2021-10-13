package authx

import (
	"time"

	"gitlab.me/common/toolx/encryptx"
)

type TokenBaseAseEncoder struct {
	key []byte
}

func NewTokenBaseAseEnDecoder(key []byte) *TokenBaseAseEncoder {
	return &TokenBaseAseEncoder{key: key}
}

func (m *TokenBaseAseEncoder) Encode(userNo uint64, clientID string) ([]byte, error) {
	tmp := &TokenBase{
		UserNo:   userNo,
		ClientID: clientID,
		Ts:       uint64(time.Now().UnixNano()),
	}

	if b, err := tmp.MarshalText(); err != nil {
		return nil, err
	} else {
		return encryptx.EncryptAES(b, m.key)
	}
}

func (m *TokenBaseAseEncoder) Decode(b []byte) (*TokenBase, error) {
	d := &TokenBase{}
	if db, err := encryptx.DecryptAES(b, m.key); err != nil {
		return nil, err
	} else if err := d.UnmarshalText(db); err != nil {
		return nil, err
	}
	return d, nil
}
