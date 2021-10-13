package encryptx

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

type XRsaEncrypter struct {
	pub *rsa.PublicKey
	pri *rsa.PrivateKey
}

func NewXRsaEncrypter(pri *rsa.PrivateKey, pub *rsa.PublicKey) *XRsaEncrypter {
	return &XRsaEncrypter{
		pri: pri,
		pub: pub,
	}
}

func NewXRsaEncrypterWithPrivateBytesHard(pri []byte) *XRsaEncrypter {
	x, err := NewXRsaEncrypterWithPrivateBytes(pri)
	if err != nil {
		panic(err)
	}
	return x
}

func NewXRsaEncrypterWithPublicBytesHard(pub []byte) *XRsaEncrypter {
	x, err := NewXRsaEncrypterWithPublicBytes(pub)
	if err != nil {
		panic(err)
	}
	return x
}

func NewXRsaEncrypterWithPrivateBytes(pri []byte) (*XRsaEncrypter, error) {
	block, _ := pem.Decode(pri)
	if block == nil {
		return nil, errors.New("private key error!")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes) //解析pem.Decode（）返回的Block指针实例
	if err != nil {
		return nil, err
	}
	return &XRsaEncrypter{
		pri: priv,
		pub: &priv.PublicKey,
	}, nil
}

func NewXRsaEncrypterWithPublicBytes(pub []byte) (*XRsaEncrypter, error) {
	block, _ := pem.Decode(pub)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &XRsaEncrypter{
		pub: pubInterface.(*rsa.PublicKey),
	}, nil
}

func (m *XRsaEncrypter) EncodeOAEP(origData []byte) ([]byte, error) {
	// partLen := m.pub.N.BitLen()/8 - 11
	// chunks := split(origData, partLen)
	// buffer := bytes.NewBufferString("")
	// for _, chunk := range chunks {
	// 	bytes, err := rsa.EncryptPKCS1v15(rand.Reader, m.pub, chunk)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	buffer.Write(bytes)
	// }
	// ciphertext, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, m.pub, origData, nil)
	// if err != nil {
	// 	log.Error(err)
	// }
	// return buffer.Bytes(), nil
	// return rsa.EncryptPKCS1v15(rand.Reader, m.pub, origData)
	hash := sha256.New()
	msgLen := len(origData)
	step := m.pub.Size() - 2*hash.Size() - 2
	var encryptedBytes []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		encryptedBlockBytes, err := rsa.EncryptOAEP(hash, rand.Reader, m.pub, origData[start:finish], nil)
		if err != nil {
			return nil, err
		}

		encryptedBytes = append(encryptedBytes, encryptedBlockBytes...)
	}

	return encryptedBytes, nil
	// return rsa.EncryptOAEP(sha256.New(), rand.Reader, m.pub, origData, nil)
}

func (m *XRsaEncrypter) DecodeOAEP(ciphertext []byte) ([]byte, error) {
	if m.pri == nil {
		return nil, errors.New("Can't decode without private key")
	}
	hash := sha256.New()
	msgLen := len(ciphertext)
	step := m.pub.Size()
	var decryptedBytes []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		decryptedBlockBytes, err := rsa.DecryptOAEP(hash, rand.Reader, m.pri, ciphertext[start:finish], nil)
		if err != nil {
			return nil, err
		}

		decryptedBytes = append(decryptedBytes, decryptedBlockBytes...)
	}

	return decryptedBytes, nil
	// hash := sha512.New()
	// return rsa.DecryptOAEP(sha256.New(), rand.Reader, m.pri, ciphertext, nil)
	// partLen := m.pub.N.BitLen() / 8
	// // raw, err := base64.RawURLEncoding.DecodeString(encrypted)
	// chunks := split(ciphertext, partLen)
	// buffer := bytes.NewBufferString("")
	// for _, chunk := range chunks {
	// 	decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, m.pri, chunk)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	buffer.Write(decrypted)
	// }
	// return buffer.Bytes(), nil
	// partLen := m.pub.N.BitLen()/8 - 11
	// chunks := split(ciphertext, partLen)
	// buffer := bytes.NewBufferString("")
	// for _, chunk := range chunks {
	// 	bytes, err := rsa.EncryptPKCS1v15(rand.Reader, m.pub, chunk)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	buffer.Write(bytes)
	// }
	// return buffer.Bytes(), nil
}

/*
----------- Sign and Verify
*/
// func (m *XRsaEncrypter) Sign(hash crypto.Hash, hashed []byte) ([]byte, error) {
// 	if m.pri == nil {
// 		return nil, errors.New("Can't sign without private key")
// 	}
// 	return rsa.SignPKCS1v15(rand.Reader, m.pri, hash, hashed)
// }

// func (m *XRsaEncrypter) Verify(hash crypto.Hash, hashed []byte, sig []byte) error {
// 	return rsa.VerifyPKCS1v15(m.pub, hash, hashed, sig)
// }

// //MD5
// func (m *XRsaEncrypter) SignMd5(hashed [16]byte) ([]byte, error) {
// 	return m.Sign(crypto.MD5, hashed[:])
// }

// func (m *XRsaEncrypter) SignMd5GetBase64(hashed [16]byte) (string, error) {
// 	b, err := m.SignMd5(hashed)
// 	if err != nil {
// 		return "", err
// 	}
// 	return base64.StdEncoding.EncodeToString(b), nil
// }

// func (m *XRsaEncrypter) SignMd5GetBase64Hard(hashed [16]byte) string {
// 	b, err := m.SignMd5(hashed)
// 	if err != nil {
// 		panic(err)
// 	}
// 	return base64.StdEncoding.EncodeToString(b)
// }

// func (m *XRsaEncrypter) VerifyMd5(hashed [16]byte, sig []byte) error {
// 	return m.Verify(crypto.MD5, hashed[:], sig)
// }

// func (m *XRsaEncrypter) VerifyMd5String(hashed [16]byte, sigBase64 string) error {
// 	b, err := base64.StdEncoding.DecodeString(sigBase64)
// 	if err != nil {
// 		return err
// 	}
// 	return m.VerifyMd5(hashed, b)
// }

// //256
// func (m *XRsaEncrypter) SignSha256(hashed [32]byte) ([]byte, error) {
// 	return m.Sign(crypto.SHA256, hashed[:])
// }

// func (m *XRsaEncrypter) SignSha256Base64(hashed [32]byte) (string, error) {
// 	b, err := m.SignSha256(hashed)
// 	if err != nil {
// 		return "", err
// 	}
// 	return base64.StdEncoding.EncodeToString(b), nil
// }

// func (m *XRsaEncrypter) SignSha256GetBase64Hard(hashed [32]byte) string {
// 	b, err := m.SignSha256(hashed)
// 	if err != nil {
// 		panic(err)
// 	}
// 	return base64.StdEncoding.EncodeToString(b)
// }

// func (m *XRsaEncrypter) VerifySha256(hashed [32]byte, sig []byte) error {
// 	return m.Verify(crypto.SHA256, hashed[:], sig)
// }

// func (m *XRsaEncrypter) VerifySha256String(hashed [32]byte, sigBase64 string) error {
// 	b, err := base64.StdEncoding.DecodeString(sigBase64)
// 	if err != nil {
// 		return err
// 	}
// 	return m.VerifySha256(hashed, b)
// }

// func split(buf []byte, lim int) [][]byte {
// 	var chunk []byte
// 	chunks := make([][]byte, 0, len(buf)/lim+1)
// 	for len(buf) >= lim {
// 		chunk, buf = buf[:lim], buf[lim:]
// 		chunks = append(chunks, chunk)
// 	}
// 	if len(buf) > 0 {
// 		chunks = append(chunks, buf[:])
// 	}
// 	return chunks
// }
