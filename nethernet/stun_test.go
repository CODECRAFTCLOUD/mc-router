package nethernet

import (
	"testing"

	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
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
