package nethernet

import (
	"net/netip"
	"testing"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func b1Backend(id string, legacy int) Backend {
	return Backend{ServerID: id, Addr: netip.MustParseAddrPort("10.96.0.10:19132"), LegacyPort: legacy, AsleepMOTD: "zzz"}
}

func TestByHostNormalizes(t *testing.T) {
	rt := NewRouteTable()
	rt.Upsert("game/mc-a", []string{"survival.uniz.host"}, b1Backend("a", 0))

	for _, h := range []string{"survival.uniz.host", "Survival.Uniz.Host.:19132", "SURVIVAL.UNIZ.HOST", "survival.uniz.host."} {
		b, ok := rt.ByHost(h)
		require.True(t, ok, h)
		assert.Equal(t, "a", b.ServerID, h)
	}
	_, ok := rt.ByHost("other.uniz.host")
	assert.False(t, ok)
	_, ok = rt.ByHost("")
	assert.False(t, ok)
}

func TestByHostNormalizesTheStoredHostsToo(t *testing.T) {
	rt := NewRouteTable()
	rt.Upsert("game/mc-a", []string{" Survival.Uniz.Host. "}, b1Backend("a", 0))
	_, ok := rt.ByHost("survival.uniz.host")
	assert.True(t, ok)
}

func TestByLegacyPort(t *testing.T) {
	rt := NewRouteTable()
	rt.Upsert("game/mc-a", []string{"a.uniz.host"}, b1Backend("a", 30001))
	rt.Upsert("game/mc-b", []string{"b.uniz.host"}, b1Backend("b", 0))

	b, ok := rt.ByLegacyPort(30001)
	require.True(t, ok)
	assert.Equal(t, "a", b.ServerID)
	_, ok = rt.ByLegacyPort(0) // a server without a legacy port is never found by 0
	assert.False(t, ok)
	_, ok = rt.ByLegacyPort(30002)
	assert.False(t, ok)

	rt.Upsert("game/mc-a", []string{"a.uniz.host"}, b1Backend("a", 30005))
	_, ok = rt.ByLegacyPort(30001)
	assert.False(t, ok, "the old legacy port is released on update")
	_, ok = rt.ByLegacyPort(30005)
	assert.True(t, ok)
}

func TestUpsertReplacesOldHosts(t *testing.T) {
	rt := NewRouteTable()
	rt.Upsert("game/mc-a", []string{"old.uniz.host", "keep.example.com"}, b1Backend("a", 0))
	rt.Upsert("game/mc-a", []string{"new.uniz.host", "keep.example.com"}, b1Backend("a", 0))

	_, ok := rt.ByHost("old.uniz.host")
	assert.False(t, ok, "a renamed server's old host no longer resolves")
	_, ok = rt.ByHost("new.uniz.host")
	assert.True(t, ok)
	_, ok = rt.ByHost("keep.example.com")
	assert.True(t, ok)
}

func TestRemoveDropsHostsAndLegacyPort(t *testing.T) {
	rt := NewRouteTable()
	rt.Upsert("game/mc-a", []string{"a.uniz.host"}, b1Backend("a", 30001))
	rt.Remove("game/mc-a")
	_, ok := rt.ByHost("a.uniz.host")
	assert.False(t, ok)
	_, ok = rt.ByLegacyPort(30001)
	assert.False(t, ok)
	rt.Remove("game/never-seen") // no panic
}

func TestRemoveLeavesAHostAnotherServiceTookOver(t *testing.T) {
	rt := NewRouteTable()
	rt.Upsert("game/mc-a", []string{"shared.uniz.host"}, b1Backend("a", 30001))
	rt.Upsert("game/mc-b", []string{"shared.uniz.host"}, b1Backend("b", 30001))
	rt.Remove("game/mc-a")

	b, ok := rt.ByHost("shared.uniz.host")
	require.True(t, ok)
	assert.Equal(t, "b", b.ServerID)
	b, ok = rt.ByLegacyPort(30001)
	require.True(t, ok)
	assert.Equal(t, "b", b.ServerID)
}

// Routable Services are named mc-<ObjectId>, and an ObjectId starts with its
// creation time, so the higher name is the newer server.
const (
	b1Older = "game/mc-65f0c0ff0000000000000001" // e.g. leaked by a deleted server
	b1Newer = "game/mc-670d1e5a0000000000000002" // the live server that reused the slug/port
)

// M-2 / N-2: a leaked Service can claim a live server's host or pool port.
// Every replica must pick the same winner, the highest svcKey (the newest
// server), whatever the event order, and a slice event re-running Upsert on
// the loser must not flip it.
func TestRouteTableTwoClaimsPickTheSameWinnerInAnyOrder(t *testing.T) {
	for _, order := range [][]string{{b1Older, b1Newer}, {b1Newer, b1Older}} {
		rt := NewRouteTable()
		for _, key := range order {
			rt.Upsert(key, []string{"shared.uniz.host"}, b1Backend(key, 30001))
		}
		rt.Upsert(b1Older, []string{"shared.uniz.host"}, b1Backend(b1Older, 30001)) // a slice event

		b, ok := rt.ByHost("shared.uniz.host")
		require.True(t, ok, order)
		assert.Equal(t, b1Newer, b.ServerID, order)
		b, ok = rt.ByLegacyPort(30001)
		require.True(t, ok, order)
		assert.Equal(t, b1Newer, b.ServerID, order)
	}
}

func TestRouteTableFallsBackWhenTheWinnerIsRemoved(t *testing.T) {
	for _, order := range [][]string{{b1Older, b1Newer}, {b1Newer, b1Older}} {
		rt := NewRouteTable()
		for _, key := range order {
			rt.Upsert(key, []string{"shared.uniz.host"}, b1Backend(key, 30001))
		}
		rt.Remove(b1Newer)

		b, ok := rt.ByHost("shared.uniz.host")
		require.True(t, ok, order)
		assert.Equal(t, b1Older, b.ServerID, order, "the next claimant takes over")
		b, ok = rt.ByLegacyPort(30001)
		require.True(t, ok, order)
		assert.Equal(t, b1Older, b.ServerID, order)

		rt.Remove(b1Older)
		_, ok = rt.ByHost("shared.uniz.host")
		assert.False(t, ok, order)
		_, ok = rt.ByLegacyPort(30001)
		assert.False(t, ok, order)
	}
}

// N-2: a contested claim is logged once when it starts and once when it ends,
// naming both Services; a slice event re-running Upsert logs nothing.
func TestRouteTableWarnsWhenAClaimGainsOrLosesASecondClaimant(t *testing.T) {
	hook := logrustest.NewGlobal()
	t.Cleanup(func() { logrus.StandardLogger().ReplaceHooks(logrus.LevelHooks{}) })
	warnings := func() (out []*logrus.Entry) {
		for _, e := range hook.AllEntries() {
			if e.Level == logrus.WarnLevel {
				out = append(out, e)
			}
		}
		hook.Reset()
		return out
	}
	rt := NewRouteTable()
	rt.Upsert(b1Older, []string{"shared.uniz.host"}, b1Backend(b1Older, 30001))
	assert.Empty(t, warnings(), "one claimant is no conflict")

	rt.Upsert(b1Newer, []string{"shared.uniz.host"}, b1Backend(b1Newer, 30001))
	got := warnings()
	require.Len(t, got, 2, "the host and the legacy port each gained a second claimant")
	for _, e := range got {
		assert.Equal(t, []string{b1Older, b1Newer}, e.Data["claimants"])
		assert.Equal(t, b1Newer, e.Data["service"], "names the Service that joined")
		assert.Equal(t, b1Newer, e.Data["winner"], "names who serves the route now")
	}

	rt.Upsert(b1Older, []string{"shared.uniz.host"}, b1Backend(b1Older, 30001)) // a slice event
	rt.Upsert(b1Newer, []string{"shared.uniz.host"}, b1Backend(b1Newer, 30001))
	assert.Empty(t, warnings(), "an unchanged claim logs nothing")

	rt.Remove(b1Newer)
	got = warnings()
	require.Len(t, got, 2, "the host and the legacy port each lost their second claimant")
	for _, e := range got {
		assert.Equal(t, []string{b1Older, b1Newer}, e.Data["claimants"])
		assert.Equal(t, b1Newer, e.Data["service"], "names the Service that left")
		assert.Equal(t, b1Older, e.Data["winner"], "names who serves the route now")
	}
}
