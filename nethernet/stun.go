package nethernet

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
)

const (
	stunHeaderLen      = 20
	stunMagicCookie    = 0x2112A442
	stunAttrUsername   = 0x0006
	stunAttrIntegrity  = 0x0008
	stunIntegritySize  = 20
	stunAttrHeaderSize = 4
)

// IsSTUN reports whether pkt carries a STUN header (RFC 5389 §6). The first
// byte is held to 0..3, the RFC 7983 demux range, which implies the top two bits
// are 0 and keeps a DTLS record (20..63) out even if bytes 4..7 match the cookie.
func IsSTUN(pkt []byte) bool {
	return len(pkt) >= stunHeaderLen && pkt[0] < 4 &&
		binary.BigEndian.Uint32(pkt[4:8]) == stunMagicCookie
}

// stunAttrs calls fn for each attribute with its start offset and value, until
// fn returns false. It stops at the first attribute that runs past the message.
func stunAttrs(pkt []byte, fn func(off int, typ uint16, val []byte) bool) {
	if !IsSTUN(pkt) {
		return
	}
	end := stunHeaderLen + int(binary.BigEndian.Uint16(pkt[2:4]))
	if end > len(pkt) {
		return
	}
	for off := stunHeaderLen; off+stunAttrHeaderSize <= end; {
		typ := binary.BigEndian.Uint16(pkt[off:])
		n := int(binary.BigEndian.Uint16(pkt[off+2:]))
		valEnd := off + stunAttrHeaderSize + n
		if valEnd > end {
			return
		}
		if !fn(off, typ, pkt[off+stunAttrHeaderSize:valEnd]) {
			return
		}
		off = valEnd + (4-n%4)%4
	}
}

// STUNUsername returns the USERNAME attribute ("serverUfrag:clientUfrag" on a check from the client).
func STUNUsername(pkt []byte) (string, bool) {
	var user string
	found := false
	stunAttrs(pkt, func(_ int, typ uint16, val []byte) bool {
		if typ == stunAttrUsername {
			user, found = string(val), true
			return false
		}
		return true
	})
	return user, found
}

// VerifyIntegrity checks MESSAGE-INTEGRITY with the short-term key password
// (RFC 5389 §15.4). Anything after the attribute (FINGERPRINT) is not covered.
func VerifyIntegrity(pkt []byte, password string) bool {
	ok := false
	stunAttrs(pkt, func(off int, typ uint16, val []byte) bool {
		if typ != stunAttrIntegrity {
			return true
		}
		if len(val) != stunIntegritySize {
			return false
		}
		covered := append([]byte(nil), pkt[:off]...)
		binary.BigEndian.PutUint16(covered[2:4], uint16(off-stunHeaderLen+stunAttrHeaderSize+stunIntegritySize))
		mac := hmac.New(sha1.New, []byte(password))
		mac.Write(covered)
		ok = hmac.Equal(mac.Sum(nil), val)
		return false
	})
	return ok
}
