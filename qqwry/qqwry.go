package qqwry

import (
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/text/encoding/simplifiedchinese"
	"io/ioutil"
	"net"
	"os"
	"strings"
)

const (
	IdxLen = 7
	Mode1  = 0x01
	Mode2  = 0x02
)

// Reference https://metacpan.org/pod/IP::QQWry

type QQwry struct {
	firstIdx uint32
	lastIdx  uint32
}

//go:embed qqwry.dat
var dat []byte

func New(filePath string) (qqwry QQwry, err error) {
	if filePath != "" {
		_, err := os.Stat(filePath)
		if err != nil {
			return qqwry, err
		}

		path, err := os.OpenFile(filePath, os.O_RDONLY, 0400)
		if err != nil {
			return qqwry, err
		}
		defer path.Close()

		dat, err = ioutil.ReadAll(path)
		if err != nil {
			return qqwry, err
		}
	}

	qqwry = QQwry{
		firstIdx: binary.LittleEndian.Uint32(dat[0:4]),
		lastIdx:  binary.LittleEndian.Uint32(dat[4:8]),
	}

	return
}

func (q *QQwry) Count() int64 {
	return int64((q.lastIdx-q.firstIdx)/IdxLen + 1)
}

func (q *QQwry) Version() string {
	base, ext, _ := q.QueryString("255.255.255.0") // db version info is held there
	return fmt.Sprintf("%s %s 共%d条数据", base, ext, q.Count())
}

func (q *QQwry) QueryInfo(ipv4 string) (info string, err error) {
	base, ext, err := q.QueryString(ipv4)
	if err != nil {
		return
	}
	if ext == "" {
		info = base
	} else {
		info = base + "," + ext
	}

	return
}

func (q *QQwry) QueryString(ipv4 string) (base string, ext string, err error) {
	ip := net.ParseIP(ipv4).To4()
	if ip == nil {
		err = errors.New("not IPv4 address string")
		return
	}

	return q.QueryIP(ip)
}

func (q *QQwry) QueryIP(ipv4 net.IP) (base string, ext string, err error) {
	return q.QueryInt(binary.BigEndian.Uint32(ipv4))
}

func (q *QQwry) QueryInt(ipv4 uint32) (base string, ext string, err error) {
	index := q.index(ipv4)
	if index <= 0 {
		err = errors.New("can't find index")
		return
	}

	var (
		baseBuf []byte
		extBuf  []byte
	)

	offset := q.readNewOffset(index + 4)
	mode := dat[offset+4 : offset+4+1][0]

	if mode == Mode1 {
		offset = q.readNewOffset(offset + 4 + 1)
		if dat[offset : offset+1][0] == Mode2 {
			baseBuf, _ = q.str(q.readNewOffset(offset + 1))
			extBuf, _ = q.ext(offset + 4)
		} else {
			baseBuf, offset = q.str(offset)
			extBuf, _ = q.ext(offset)
		}
	} else if mode == Mode2 {
		baseBuf, _ = q.str(q.readNewOffset(offset + 4 + 1))
		extBuf, _ = q.ext(offset + 8)
	} else {
		baseBuf, offset = q.str(offset + 4)
		extBuf, _ = q.ext(offset)
	}

	enc := simplifiedchinese.GBK.NewDecoder()
	if base, err = enc.String(string(baseBuf)); err != nil {
		return
	}
	if ext, err = enc.String(string(extBuf)); err != nil {
		return
	}

	// 'CZ88.NET' means we don't have useful information
	base = strings.ReplaceAll(base, " CZ88.NET", "")
	ext = strings.ReplaceAll(ext, " CZ88.NET", "")

	return
}

func (q *QQwry) str(offset uint32) ([]byte, uint32) {
	buf := make([]byte, 0, 20)
	for dat[offset] > 0 {
		buf = append(buf, dat[offset])
		offset++
	}

	return buf, offset + 1
}

func (q *QQwry) ext(offset uint32) ([]byte, uint32) {
	mode := dat[offset : offset+1][0]
	if mode == Mode1 || mode == Mode2 {
		return q.str(q.readNewOffset(offset + 1))
	}

	return q.str(offset)
}

func (q *QQwry) index(ip uint32) uint32 {
	var (
		up      = (q.lastIdx - q.firstIdx) / IdxLen
		low     = uint32(0)
		mid     = uint32(0)
		ipStart = uint32(0)
		ipEnd   = uint32(0)
	)

	for low <= up {
		mid = (low + up) / 2
		offset := q.firstIdx + mid*IdxLen
		ipStart = binary.LittleEndian.Uint32(dat[offset : offset+4])

		if ip < ipStart {
			up = mid - 1
		} else {
			offset = q.readNewOffset(offset + 4)
			ipEnd = binary.LittleEndian.Uint32(dat[offset : offset+4])

			if ip > ipEnd {
				low = mid + 1
			} else {
				return q.firstIdx + mid*IdxLen
			}
		}
	}

	return 0
}

func (q *QQwry) readNewOffset(offset uint32) uint32 {
	i := uint32(dat[offset]) & 0xff
	i |= (uint32(dat[offset+1]) << 8) & 0xff00
	i |= (uint32(dat[offset+2]) << 16) & 0xff0000
	return i
}
