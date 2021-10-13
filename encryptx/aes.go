package encryptx

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func padding(src []byte, blocksize int) []byte {
	padnum := blocksize - len(src)%blocksize
	pad := bytes.Repeat([]byte{byte(padnum)}, padnum)
	return append(src, pad...)
}

func unpadding(src []byte) []byte {
	n := len(src)
	unpadnum := int(src[n-1])
	return src[:n-unpadnum]
}

//EncryptAES 加密
func EncryptAES(src []byte, key []byte) (ret []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			ret = nil
			err = fmt.Errorf("%v", r)
		}
	}()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	src = padding(src, block.BlockSize())
	blockmode := cipher.NewCBCEncrypter(block, key)
	blockmode.CryptBlocks(src, src)
	return src, nil
}

//DecryptAES 解密
func DecryptAES(src []byte, key []byte) (ret []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			ret = nil
			err = fmt.Errorf("%v", r)
		}
	}()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockmode := cipher.NewCBCDecrypter(block, key)
	blockmode.CryptBlocks(src, src)
	src = unpadding(src)
	return src, nil
}
