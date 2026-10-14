package nethernet

import (
	"testing"

	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPwd = "77jVAiq4D6YxKEPgZS2kvTfD"

func signedBinding(username, pwd string) []byte {
	return stun.MustBuild(stun.TransactionID, stun.BindingRequest, stun.NewUsername(username),
		stun.NewShortTermIntegrity(pwd), stun.Fingerprint).Raw
}

func TestSTUNUsernameReadsThePair(t *testing.T) {
	pkt := signedBinding("2c69:QXyz", testPwd)
	assert.True(t, IsSTUN(pkt))
	u, ok := STUNUsername(pkt)
	assert.True(t, ok)
	assert.Equal(t, "2c69:QXyz", u)
}

func TestVerifyIntegrityAcceptsTheRightPassword(t *testing.T) {
	assert.True(t, VerifyIntegrity(signedBinding("2c69:QXyz", testPwd), testPwd))
}

func TestVerifyIntegrityAcceptsWithoutFingerprint(t *testing.T) {
	pkt := stun.MustBuild(stun.TransactionID, stun.BindingRequest, stun.NewUsername("2c69:QXyz"),
		stun.NewShortTermIntegrity(testPwd)).Raw
	assert.True(t, VerifyIntegrity(pkt, testPwd))
}

func TestVerifyIntegrityRejectsAWrongPassword(t *testing.T) {
	assert.False(t, VerifyIntegrity(signedBinding("2c69:QXyz", testPwd), "wrong-password-0000000"))
}

func TestVerifyIntegrityRejectsATamperedUsername(t *testing.T) {
	pkt := signedBinding("2c69:QXyz", testPwd)
	pkt[24+0] ^= 0x01 // first byte of the USERNAME value
	assert.False(t, VerifyIntegrity(pkt, testPwd))
}

func TestVerifyIntegrityRejectsNoIntegrity(t *testing.T) {
	pkt := stun.MustBuild(stun.TransactionID, stun.BindingRequest, stun.NewUsername("2c69:QXyz"), stun.Fingerprint).Raw
	assert.False(t, VerifyIntegrity(pkt, testPwd))
}

func TestIsSTUNRejectsDTLS(t *testing.T) {
	pkt := signedBinding("2c69:QXyz", testPwd)
	pkt[0] = 0x16
	assert.False(t, IsSTUN(pkt))
	assert.False(t, IsSTUN([]byte{0x16, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}))
}

func TestSTUNParsersNeverPanicOnShortInput(t *testing.T) {
	pkt := signedBinding("2c69:QXyz", testPwd)
	for n := 0; n <= 64 && n <= len(pkt); n++ {
		p := append([]byte(nil), pkt[:n]...)
		assert.NotPanics(t, func() {
			IsSTUN(p)
			STUNUsername(p)
			VerifyIntegrity(p, testPwd)
		})
	}
	// A header that claims more attribute bytes than it carries.
	lying := append([]byte(nil), pkt[:20]...)
	lying[2], lying[3] = 0xff, 0xfc
	assert.NotPanics(t, func() { STUNUsername(lying); VerifyIntegrity(lying, testPwd) })
	// An attribute whose length runs past the end.
	bad := append([]byte(nil), pkt[:28]...)
	bad[2], bad[3] = 0, 8
	bad[22], bad[23] = 0xff, 0xff
	assert.NotPanics(t, func() { STUNUsername(bad); VerifyIntegrity(bad, testPwd) })
}

// controllingCheck is a client connectivity check as an ICE-controlling agent
// sends it: USERNAME, ICE-CONTROLLING, PRIORITY, then MESSAGE-INTEGRITY and FINGERPRINT.
func controllingCheck(t *testing.T, extra ...stun.Setter) *stun.Message {
	t.Helper()
	setters := []stun.Setter{stun.TransactionID, stun.BindingRequest, stun.NewUsername(testPair),
		stun.RawAttribute{Type: stun.AttrICEControlling, Value: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		stun.RawAttribute{Type: stun.AttrPriority, Value: []byte{0x6e, 0, 0x1e, 0xff}}}
	setters = append(setters, extra...)
	setters = append(setters, stun.NewShortTermIntegrity(testPwd), stun.Fingerprint)
	return stun.MustBuild(setters...)
}

func decoded(t *testing.T, raw []byte) *stun.Message {
	t.Helper()
	m := &stun.Message{Raw: append([]byte(nil), raw...)}
	require.NoError(t, m.Decode())
	return m
}

func TestAddUseCandidateNominatesAndReSignsAControllingCheck(t *testing.T) {
	in := controllingCheck(t)
	before := append([]byte(nil), in.Raw...)
	out, ok := addUseCandidate(in.Raw, testPwd)
	require.True(t, ok)
	m := decoded(t, out)
	assert.True(t, m.Contains(stun.AttrUseCandidate))
	assert.Equal(t, in.TransactionID, m.TransactionID, "the transaction id is kept")
	assert.Equal(t, stun.BindingRequest, m.Type)
	assert.True(t, VerifyIntegrity(out, testPwd))
	require.NoError(t, stun.NewShortTermIntegrity(testPwd).Check(m))
	require.NoError(t, stun.Fingerprint.Check(m))
	var order []stun.AttrType
	for _, a := range m.Attributes {
		order = append(order, a.Type)
	}
	assert.Equal(t, []stun.AttrType{stun.AttrUsername, stun.AttrICEControlling, stun.AttrPriority,
		stun.AttrUseCandidate, stun.AttrMessageIntegrity, stun.AttrFingerprint}, order, "RFC 8489: USE-CANDIDATE before MESSAGE-INTEGRITY, FINGERPRINT last")
	assert.Equal(t, before, in.Raw, "the input buffer is not modified")
}

func TestAddUseCandidateKeepsAMissingFingerprintMissing(t *testing.T) {
	in := stun.MustBuild(stun.TransactionID, stun.BindingRequest, stun.NewUsername(testPair),
		stun.RawAttribute{Type: stun.AttrICEControlling, Value: make([]byte, 8)}, stun.NewShortTermIntegrity(testPwd))
	out, ok := addUseCandidate(in.Raw, testPwd)
	require.True(t, ok)
	m := decoded(t, out)
	assert.True(t, m.Contains(stun.AttrUseCandidate))
	assert.False(t, m.Contains(stun.AttrFingerprint))
	require.NoError(t, stun.NewShortTermIntegrity(testPwd).Check(m))
}

// A check that already nominates is forwarded byte-identical, never re-signed.
func TestAddUseCandidateLeavesANominatingCheckByteIdentical(t *testing.T) {
	in := controllingCheck(t, stun.RawAttribute{Type: stun.AttrUseCandidate})
	out, ok := addUseCandidate(in.Raw, testPwd)
	assert.False(t, ok)
	assert.Equal(t, in.Raw, out)
}

func TestAddUseCandidateLeavesEverythingElseUntouched(t *testing.T) {
	controlled := stun.MustBuild(stun.TransactionID, stun.BindingRequest, stun.NewUsername(testPair),
		stun.RawAttribute{Type: stun.AttrICEControlled, Value: make([]byte, 8)}, stun.NewShortTermIntegrity(testPwd), stun.Fingerprint)
	response := stun.MustBuild(stun.TransactionID, stun.BindingSuccess,
		stun.RawAttribute{Type: stun.AttrICEControlling, Value: make([]byte, 8)}, stun.NewShortTermIntegrity(testPwd), stun.Fingerprint)
	unsigned := stun.MustBuild(stun.TransactionID, stun.BindingRequest, stun.NewUsername(testPair),
		stun.RawAttribute{Type: stun.AttrICEControlling, Value: make([]byte, 8)}, stun.Fingerprint)
	wrongPwd := stun.MustBuild(stun.TransactionID, stun.BindingRequest, stun.NewUsername(testPair),
		stun.RawAttribute{Type: stun.AttrICEControlling, Value: make([]byte, 8)}, stun.NewShortTermIntegrity("someone-else-password-00"), stun.Fingerprint)
	afterIntegrity := controllingCheck(t)
	trailing := append(append([]byte(nil), afterIntegrity.Raw...), 0, 0, 0, 0) // bytes past the STUN length
	for name, pkt := range map[string][]byte{
		"dtls":                 dtlsData,
		"no ICE-CONTROLLING":   controlled.Raw,
		"binding response":     response.Raw,
		"no integrity":         unsigned.Raw,
		"another password":     wrongPwd.Raw,
		"datagram past length": trailing,
		"empty":                {},
	} {
		out, ok := addUseCandidate(pkt, testPwd)
		assert.False(t, ok, name)
		assert.Equal(t, pkt, out, name)
	}
}

func TestAddUseCandidateNeverPanicsOnShortInput(t *testing.T) {
	pkt := controllingCheck(t).Raw
	for n := 0; n <= len(pkt); n++ {
		p := append([]byte(nil), pkt[:n]...)
		assert.NotPanics(t, func() { addUseCandidate(p, testPwd) })
	}
}
