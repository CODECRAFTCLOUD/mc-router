package nethernet

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"hash/crc32"
)

const (
	stunHeaderLen      = 20
	stunMagicCookie    = 0x2112A442
	stunAttrUsername   = 0x0006
	stunAttrIntegrity  = 0x0008
	stunIntegritySize  = 20
	stunAttrHeaderSize = 4

	stunBindingRequest     = 0x0001
	stunBindingSuccess     = 0x0101
	stunAttrUseCandidate   = 0x0025
	stunAttrFingerprint    = 0x8028
	stunAttrICEControlling = 0x802A
	stunFingerprintXOR     = 0x5354554e
	stunFingerprintSize    = 4
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

// addUseCandidate returns a copy of a client's Binding Request with USE-CANDIDATE
// (RFC 8445 section 7.1.2) added before MESSAGE-INTEGRITY, re-signed with
// password and, when the request had one, a new FINGERPRINT last (RFC 8489
// section 14). It returns pkt itself and false for anything else: a request
// without ICE-CONTROLLING or a valid MESSAGE-INTEGRITY, one that already
// carries USE-CANDIDATE, one with attributes after MESSAGE-INTEGRITY other than
// FINGERPRINT, and every response, DTLS or non-STUN datagram. Only a request
// the server would accept anyway is re-signed.
func addUseCandidate(pkt []byte, password string) ([]byte, bool) {
	if !IsSTUN(pkt) || binary.BigEndian.Uint16(pkt[0:2]) != stunBindingRequest ||
		stunHeaderLen+int(binary.BigEndian.Uint16(pkt[2:4])) != len(pkt) {
		return pkt, false
	}
	mi, controlling, nominated := -1, false, false
	stunAttrs(pkt, func(off int, typ uint16, _ []byte) bool {
		switch typ {
		case stunAttrICEControlling:
			controlling = true
		case stunAttrUseCandidate:
			nominated = true
		case stunAttrIntegrity:
			mi = off
			return false
		}
		return true
	})
	if mi < 0 || !controlling || nominated {
		return pkt, false
	}
	rest := pkt[mi+stunAttrHeaderSize+stunIntegritySize:]
	fingerprint := len(rest) == stunAttrHeaderSize+stunFingerprintSize &&
		binary.BigEndian.Uint16(rest) == stunAttrFingerprint
	if len(rest) != 0 && !fingerprint || !VerifyIntegrity(pkt, password) {
		return pkt, false
	}
	out := make([]byte, 0, len(pkt)+stunAttrHeaderSize)
	out = append(out, pkt[:mi]...)
	out = binary.BigEndian.AppendUint16(out, stunAttrUseCandidate)
	out = binary.BigEndian.AppendUint16(out, 0)
	// The header length covers MESSAGE-INTEGRITY when the HMAC is taken, and
	// FINGERPRINT when the CRC is.
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)-stunHeaderLen+stunAttrHeaderSize+stunIntegritySize))
	mac := hmac.New(sha1.New, []byte(password))
	mac.Write(out)
	out = binary.BigEndian.AppendUint16(out, stunAttrIntegrity)
	out = binary.BigEndian.AppendUint16(out, stunIntegritySize)
	out = mac.Sum(out)
	if fingerprint {
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out)-stunHeaderLen+stunAttrHeaderSize+stunFingerprintSize))
		crc := crc32.ChecksumIEEE(out) ^ stunFingerprintXOR
		out = binary.BigEndian.AppendUint16(out, stunAttrFingerprint)
		out = binary.BigEndian.AppendUint16(out, stunFingerprintSize)
		out = binary.BigEndian.AppendUint32(out, crc)
	}
	return out, true
}
