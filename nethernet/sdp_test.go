package nethernet

import (
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readGolden(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	return string(b)
}

func lineWithPrefix(sdp, prefix string) string {
	for _, l := range strings.Split(sdp, "\r\n") {
		if strings.HasPrefix(l, prefix) {
			return l
		}
	}
	return ""
}

func TestParseSDPReadsTheRealAnswer(t *testing.T) {
	info, err := ParseSDP(readGolden(t, "answer-bds-1.26.52.3.sdp"))
	require.NoError(t, err)
	assert.Equal(t, "2c69", info.IceUfrag)
	assert.Equal(t, "77jVAiq4D6YxKEPgZS2kvTfD", info.IcePwd)
	require.Len(t, info.Candidates, 4)
	for _, c := range info.Candidates {
		assert.Equal(t, uint16(19140), c.Addr.Port())
		assert.Equal(t, "host", c.Typ)
	}
	assert.Equal(t, "169.254.83.107", info.Candidates[0].Addr.Addr().String())
}

func TestParseSDPReadsTheRealOffer(t *testing.T) {
	info, err := ParseSDP(readGolden(t, "offer-win-1.26.52.sdp"))
	require.NoError(t, err)
	assert.Equal(t, "QXyz", info.IceUfrag)
	assert.Equal(t, "ux+gExhH5BpU/3zuTsUM1vL8", info.IcePwd)
	require.Len(t, info.Candidates, 4)
}

func TestPickRelayTargetSkipsLinkLocal(t *testing.T) {
	info, err := ParseSDP(readGolden(t, "answer-bds-1.26.52.3.sdp"))
	require.NoError(t, err)
	target, err := PickRelayTarget(info.Candidates)
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddrPort("10.0.0.3:19140"), target)
}

func TestPickRelayTargetRejectsLoopbackOnly(t *testing.T) {
	_, err := PickRelayTarget([]Candidate{{Addr: netip.MustParseAddrPort("127.0.0.1:19132"), Typ: "host"}})
	assert.Error(t, err)
}

func TestPickRelayTargetSkipsNonHostAndIPv6(t *testing.T) {
	target, err := PickRelayTarget([]Candidate{
		{Addr: netip.MustParseAddrPort("10.0.0.9:1"), Typ: "srflx"},
		{Addr: netip.MustParseAddrPort("[fd00::1]:2"), Typ: "host"},
		{Addr: netip.MustParseAddrPort("10.0.0.4:3"), Typ: "host"},
	})
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddrPort("10.0.0.4:3"), target)
}

func TestRewriteAnswerKeepsIdentityAndFingerprint(t *testing.T) {
	in := readGolden(t, "answer-bds-1.26.52.3.sdp")
	out, err := RewriteAnswer(in, netip.MustParseAddrPort("82.26.104.95:19132"))
	require.NoError(t, err)

	assert.Equal(t, 1, strings.Count(out, "a=candidate"))
	assert.Contains(t, out, "\r\na=candidate:1 1 udp 2122260223 82.26.104.95 19132 typ host generation 0\r\n")
	assert.Contains(t, out, "\r\nm=application 19132 UDP/DTLS/SCTP webrtc-datachannel\r\n")
	assert.Contains(t, out, "\r\nc=IN IP4 82.26.104.95\r\n")
	assert.Equal(t, lineWithPrefix(in, "a=identity:"), lineWithPrefix(out, "a=identity:"))
	assert.Equal(t, lineWithPrefix(in, "a=fingerprint:"), lineWithPrefix(out, "a=fingerprint:"))
	assert.True(t, strings.HasSuffix(out, "\r\n"))
	assert.NotContains(t, strings.ReplaceAll(out, "\r\n", ""), "\n", "every line ends in CRLF")

	info, err := ParseSDP(out)
	require.NoError(t, err)
	assert.Equal(t, "2c69", info.IceUfrag)
	assert.Equal(t, "77jVAiq4D6YxKEPgZS2kvTfD", info.IcePwd)

	// Every non-candidate line other than m= and c= is byte-for-byte.
	var kept []string
	for _, l := range strings.Split(in, "\r\n") {
		if !strings.HasPrefix(l, "a=candidate") && !strings.HasPrefix(l, "m=") && !strings.HasPrefix(l, "c=") {
			kept = append(kept, l)
		}
	}
	var gotKept []string
	for _, l := range strings.Split(out, "\r\n") {
		if !strings.HasPrefix(l, "a=candidate") && !strings.HasPrefix(l, "m=") && !strings.HasPrefix(l, "c=") {
			gotKept = append(gotKept, l)
		}
	}
	assert.Equal(t, kept, gotKept)
}

func TestRewriteAnswerAcceptsBareLF(t *testing.T) {
	in := strings.ReplaceAll(readGolden(t, "answer-bds-1.26.52.3.sdp"), "\r\n", "\n")
	out, err := RewriteAnswer(in, netip.MustParseAddrPort("82.26.104.95:19132"))
	require.NoError(t, err)
	assert.NotContains(t, strings.ReplaceAll(out, "\r\n", ""), "\n")
	assert.Equal(t, 1, strings.Count(out, "a=candidate"))
}

func TestRewriteAnswerFailsWithoutMediaSection(t *testing.T) {
	_, err := RewriteAnswer("v=0\r\ns=-\r\nt=0 0\r\na=ice-ufrag:abcd\r\n", netip.MustParseAddrPort("82.26.104.95:19132"))
	assert.Error(t, err)
}
