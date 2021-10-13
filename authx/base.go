package authx

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"gitlab.me/common/toolx"
)

func checkSum(data []byte) uint16 {
	var (
		sum    uint32
		length int = len(data)
		index  int
	)
	//以每16位为单位进行求和，直到所有的字节全部求完或者只剩下一个8位字节（如果剩余一个8位字节说明字节数为奇数个）
	for length > 1 {
		sum += uint32(data[index])<<8 + uint32(data[index+1])
		index += 2
		length -= 2
	}
	//如果字节数为奇数个，要加上最后剩下的那个8位字节
	if length > 0 {
		sum += uint32(data[index])
	}
	sum += (sum >> 16)
	//别忘了返回的时候先求反
	return uint16(^sum)
}

type TokenBase struct {
	UserNo   uint64
	Ts       uint64
	sum      uint16
	ClientID string
}

func NewTokenBase(userNo uint64, clientID string) *TokenBase {
	return (&TokenBase{
		UserNo:   userNo,
		ClientID: clientID,
		Ts:       uint64(time.Now().UnixNano()),
	}).sumIt()
}

func (m *TokenBase) sumIt() *TokenBase {
	m.sum = checkSum([]byte(fmt.Sprintf("%d_%s_%d", m.UserNo, m.ClientID, m.Ts)))
	return m
}

func (m *TokenBase) CheckSum() bool {
	return m.sum == checkSum([]byte(fmt.Sprintf("%d_%s_%d", m.UserNo, m.ClientID, m.Ts)))
}

func (m TokenBase) MarshalText() ([]byte, error) {
	var body bytes.Buffer
	m.sumIt()
	body.Write(toolx.EncodeUint64(m.UserNo))
	body.Write(toolx.EncodeUint64(m.Ts))
	body.Write(toolx.EncodeUint16(m.sum))
	body.Write(toolx.EncodeString(m.ClientID))
	return body.Bytes(), nil
}

func (m *TokenBase) UnmarshalText(text []byte) error {
	tmp := TokenBase{}
	var body = bytes.NewReader(text)
	var err error
	if tmp.UserNo, err = toolx.DecodeUint64(body); err != nil {
		return err
	}
	if tmp.Ts, err = toolx.DecodeUint64(body); err != nil {
		return err
	}
	if tmp.sum, err = toolx.DecodeUint16(body); err != nil {
		return err
	}
	if tmp.ClientID, err = toolx.DecodeString(body); err != nil {
		return err
	}

	if !tmp.CheckSum() {
		return errors.New("checkSum error")
	}
	*m = tmp
	return nil
}
