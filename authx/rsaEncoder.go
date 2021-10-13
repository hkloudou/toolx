package authx

import (
	"time"

	"gitlab.me/common/toolx/encryptx"
)

type TokenBaseRsaEncoder struct {
	rsa *encryptx.XRsaEncrypter
}

func NewTokenBaseRsaEncoder(pub []byte) *TokenBaseRsaEncoder {
	return &TokenBaseRsaEncoder{
		rsa: encryptx.NewXRsaEncrypterWithPublicBytesHard(pub),
	}
}

func NewTokenBaseRsaEnDecoder(pri []byte) *TokenBaseRsaEncoder {
	return &TokenBaseRsaEncoder{
		rsa: encryptx.NewXRsaEncrypterWithPrivateBytesHard(pri),
	}
}

func (m *TokenBaseRsaEncoder) Encode(userNo uint64, clientID string) ([]byte, error) {
	tmp := &TokenBase{
		UserNo:   userNo,
		ClientID: clientID,
		Ts:       uint64(time.Now().UnixNano()),
	}

	if b, err := tmp.MarshalText(); err != nil {
		return nil, err
	} else if b, err := m.rsa.EncodeOAEP(b); err != nil {
		return nil, err
	} else {
		return b, nil
	}
}

func (m *TokenBaseRsaEncoder) Decode(b []byte) (*TokenBase, error) {
	d := &TokenBase{}
	if db, err := m.rsa.DecodeOAEP(b); err != nil {
		return nil, err
	} else if err := d.UnmarshalText(db); err != nil {
		return nil, err
	}
	return d, nil
}
