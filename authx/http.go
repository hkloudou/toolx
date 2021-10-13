package authx

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
)

type HttpTokenHandler struct {
	face ITokenBaseEnDecoder
	sign ISigner
}

func NewHttpTokenHandler(face ITokenBaseEnDecoder, sign ISigner) *HttpTokenHandler {
	return &HttpTokenHandler{
		face: face,
		sign: sign,
	}
}

func (m *HttpTokenHandler) VerifyHttp(req *http.Request) (*TokenBase, error) {
	if req.Header.Get("authx-type") != "v1" {
		return nil, errors.New("un support")
	}

	if decoded, err := base64.StdEncoding.DecodeString(req.Header.Get("authx-token")); err != nil || len(decoded) == 0 {
		return nil, errors.New("err token format")
	} else if obj, err := m.face.Decode(decoded); err != nil || obj == nil {
		return nil, errors.New("err token format2")
	} else if req.Header.Get("authx-did") != obj.ClientID {
		return nil, errors.New("err token clientId not equal")
	} else {
		return obj, nil
	}
}

func (m *HttpTokenHandler) VerifySign(req *http.Request) error {
	if req.Header.Get("authx-type") != "v1" {
		return errors.New("un support")
	}
	ts := req.Header.Get("authx-ts")
	sign := req.Header.Get("authx-sign")
	if ts == "" {
		return errors.New("un support without ts")
	}

	if sign == "" {
		return errors.New("un support without sign")
	}

	str := req.Method + "\n" + ts + "\n" + "v1"
	var buf bytes.Buffer
	buf.Write([]byte(str))
	// log.Println(buf.Bytes(), string(buf.Bytes()))
	token := req.Header.Get("authx-token")
	if len(token) > 0 {
		tokenByte, err := base64.StdEncoding.DecodeString(token)
		if err != err {
			return errors.New("err tokenByte")
		} else {
			buf.Write(tokenByte)
		}
	}
	if m.sign == nil {
		return errors.New("not sign handle define")
	}
	return m.sign.VerifySign(buf.Bytes(), sign)
}
