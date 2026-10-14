// Package nethernet routes Bedrock NetherNet (WebRTC) joins: it rewrites the
// signaling SDP so the client talks to one public UDP port, and relays that
// UDP to the right BDS pod.
package nethernet

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type Candidate struct {
	Addr netip.AddrPort
	Typ  string
}

type SDPInfo struct {
	IceUfrag, IcePwd string
	Candidates       []Candidate
}

// sdpLines splits on "\n" and drops one trailing "\r" per line, so a line that
// carries a stray extra "\r" is written back byte-for-byte.
func sdpLines(sdp string) []string {
	lines := strings.Split(sdp, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	return lines
}

// parseCandidate reads "a=candidate:<foundation> <component> <proto> <prio> <ip> <port> typ <type> ...".
// It returns false for anything else (TCP, mDNS hostnames, malformed lines).
func parseCandidate(line string) (Candidate, bool) {
	f := strings.Fields(strings.TrimPrefix(line, "a=candidate:"))
	if len(f) < 8 || !strings.EqualFold(f[2], "udp") || f[6] != "typ" {
		return Candidate{}, false
	}
	ip, err := netip.ParseAddr(f[4])
	if err != nil {
		return Candidate{}, false
	}
	port, err := strconv.ParseUint(f[5], 10, 16)
	if err != nil {
		return Candidate{}, false
	}
	return Candidate{Addr: netip.AddrPortFrom(ip.Unmap(), uint16(port)), Typ: f[7]}, true
}

func ParseSDP(sdp string) (SDPInfo, error) {
	var info SDPInfo
	for _, l := range sdpLines(sdp) {
		switch {
		case strings.HasPrefix(l, "a=ice-ufrag:"):
			info.IceUfrag = strings.TrimSpace(strings.TrimPrefix(l, "a=ice-ufrag:"))
		case strings.HasPrefix(l, "a=ice-pwd:"):
			info.IcePwd = strings.TrimSpace(strings.TrimPrefix(l, "a=ice-pwd:"))
		case strings.HasPrefix(l, "a=candidate:"):
			if c, ok := parseCandidate(l); ok {
				info.Candidates = append(info.Candidates, c)
			}
		}
	}
	if info.IceUfrag == "" || info.IcePwd == "" {
		return info, errors.New("sdp: missing ice-ufrag or ice-pwd")
	}
	return info, nil
}

// PickRelayTarget returns the first host candidate that is IPv4, not loopback
// and not link-local: BDS does not listen for UDP on loopback.
func PickRelayTarget(cands []Candidate) (netip.AddrPort, error) {
	for _, c := range cands {
		a := c.Addr.Addr()
		if c.Typ == "host" && a.Is4() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !a.IsUnspecified() && c.Addr.Port() != 0 {
			return c.Addr, nil
		}
	}
	return netip.AddrPort{}, errors.New("sdp: no usable IPv4 host candidate")
}

// RewriteAnswer replaces every candidate with one host candidate at public and
// points the m= port and c= address at it; every other line is kept as is.
func RewriteAnswer(sdp string, public netip.AddrPort) (string, error) {
	if !public.Addr().Is4() {
		return "", fmt.Errorf("sdp: public address %s is not IPv4", public)
	}
	ip, port := public.Addr().String(), strconv.Itoa(int(public.Port()))
	candidate := "a=candidate:1 1 udp 2122260223 " + ip + " " + port + " typ host generation 0"

	var out []string
	media, cLine, placed := -1, -1, false
	for _, l := range sdpLines(sdp) {
		switch {
		case strings.HasPrefix(l, "m=application "):
			f := strings.SplitN(l, " ", 3)
			if len(f) < 3 {
				return "", errors.New("sdp: malformed m=application line")
			}
			media = len(out)
			out = append(out, f[0]+" "+port+" "+f[2])
		case strings.HasPrefix(l, "c=IN IP4 "):
			if media >= 0 {
				cLine = len(out)
			}
			out = append(out, "c=IN IP4 "+ip)
		case strings.HasPrefix(l, "a=candidate:"):
			if !placed {
				out = append(out, candidate)
				placed = true
			}
		default:
			out = append(out, l)
		}
	}
	if media < 0 {
		return "", errors.New("sdp: no m=application section")
	}
	if !placed { // an answer with no candidates still needs ours
		at := media + 1
		if cLine >= 0 {
			at = cLine + 1
		}
		out = append(out[:at], append([]string{candidate}, out[at:]...)...)
	}
	return strings.Join(out, "\r\n") + "\r\n", nil
}
