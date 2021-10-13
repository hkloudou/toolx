package toolx

import (
	"encoding/binary"
	"io"
)

func DecodeByte(b io.Reader) (byte, error) {
	num := make([]byte, 1)
	_, err := b.Read(num)
	if err != nil {
		return 0, err
	}
	return num[0], nil
}

//int
func DecodeUint16(b io.Reader) (uint16, error) {
	num := make([]byte, 2)
	_, err := b.Read(num)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(num), nil
}

func DecodeUint32(b io.Reader) (uint32, error) {
	num := make([]byte, 4)
	_, err := b.Read(num)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(num), nil
}

func DecodeUint64(b io.Reader) (uint64, error) {
	num := make([]byte, 8)
	_, err := b.Read(num)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(num), nil
}

func EncodeUint16(num uint16) []byte {
	bytesResult := make([]byte, 2)
	binary.BigEndian.PutUint16(bytesResult, num)
	return bytesResult
}

func EncodeUint32(num uint32) []byte {
	bytesResult := make([]byte, 4)
	binary.BigEndian.PutUint32(bytesResult, num)
	return bytesResult
}

func EncodeUint64(num uint64) []byte {
	bytesResult := make([]byte, 8)
	binary.BigEndian.PutUint64(bytesResult, num)
	return bytesResult
}

//bytes
func EncodeBytes(field []byte) []byte {
	// fieldLength := make([]byte, 2)
	// binary.BigEndian.PutUint16(fieldLength, uint16(len(field)))
	// EncodeLength(len(field))
	return append(EncodeLength(len(field)), field...)
}

func DecodeBytes(b io.Reader) ([]byte, error) {
	fieldLength, err := DecodeLength(b)
	if err != nil {
		return nil, err
	}

	field := make([]byte, fieldLength)
	_, err = io.ReadFull(b, field) //b.Read(field)
	if err != nil {
		return nil, err
	}

	return field, nil
}

func EncodeString(field string) []byte {
	return EncodeBytes([]byte(field))
}

func DecodeString(b io.Reader) (string, error) {
	buf, err := DecodeBytes(b)
	return string(buf), err
}

func EncodeLength(length int) []byte {
	var encLength []byte
	for {
		digit := byte(length % 128)
		length /= 128
		if length > 0 {
			digit |= 0x80
		}
		encLength = append(encLength, digit)
		if length == 0 {
			break
		}
	}
	return encLength
}
func DecodeLength(r io.Reader) (int, error) {
	var rLength uint32
	var multiplier uint32
	b := make([]byte, 1)
	for multiplier < 27 { // fix: Infinite '(digit & 128) == 1' will cause the dead loop
		_, err := io.ReadFull(r, b)
		if err != nil {
			return 0, err
		}

		digit := b[0]
		rLength |= uint32(digit&127) << multiplier
		if (digit & 128) == 0 {
			break
		}
		multiplier += 7
	}
	return int(rLength), nil
}
