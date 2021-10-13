package authx

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"

	"gitlab.me/common/toolx/encryptx"
)

type HmacSinger struct {
	key []byte
}

func NewHmacSinger(key []byte) *HmacSinger {
	return &HmacSinger{key: key}
}
func (m *HmacSinger) Sign(data []byte) (string, error) {
	mac := hmac.New(sha256.New, []byte(m.key))
	mac.Write(data)
	expectedMAC := mac.Sum(nil)
	return fmt.Sprintf("%2x", expectedMAC), nil
}

func (m *HmacSinger) VerifySign(data []byte, signed string) error {
	if d, err := m.Sign(data); err != nil {
		return err
	} else if d != signed {
		return errors.New("not equal")
	}
	return nil
}

type RsaSinger struct {
	rsa *encryptx.XRsaEncrypter
}

func NewRsaVerifySinger(pub []byte) *RsaSinger {
	return &RsaSinger{
		rsa: encryptx.NewXRsaEncrypterWithPublicBytesHard(pub),
	}
}

func NewRsaSinger(pri []byte) *RsaSinger {
	return &RsaSinger{
		rsa: encryptx.NewXRsaEncrypterWithPrivateBytesHard(pri),
	}
}

// func (m *RsaSinger) Sign(data []byte) (string, error) {
// 	return m.rsa.SignSha256Base64(sha256.Sum256(data))
// }

// func (m *RsaSinger) VerifySign(data []byte, signed string) error {
// 	return m.rsa.VerifySha256String(sha256.Sum256(data), signed)
// }
