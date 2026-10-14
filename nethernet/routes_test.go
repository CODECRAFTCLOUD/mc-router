package nethernet

import (
	"net/netip"
	"testing"

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

// M-2: a leaked Service can claim a live server's host or pool port. Every
// replica must pick the same winner (the lowest svcKey), whatever the event
// order, and a slice event re-running Upsert must not flip it.
func TestRouteTableTwoClaimsPickTheSameWinnerInAnyOrder(t *testing.T) {
	for _, order := range [][]string{{"game/mc-a", "game/mc-b"}, {"game/mc-b", "game/mc-a"}} {
		rt := NewRouteTable()
		for _, key := range order {
			rt.Upsert(key, []string{"shared.uniz.host"}, b1Backend(key, 30001))
		}
		rt.Upsert("game/mc-b", []string{"shared.uniz.host"}, b1Backend("game/mc-b", 30001)) // a slice event

		b, ok := rt.ByHost("shared.uniz.host")
		require.True(t, ok, order)
		assert.Equal(t, "game/mc-a", b.ServerID, order)
		b, ok = rt.ByLegacyPort(30001)
		require.True(t, ok, order)
		assert.Equal(t, "game/mc-a", b.ServerID, order)
	}
}

func TestRouteTableFallsBackWhenTheWinnerIsRemoved(t *testing.T) {
	for _, order := range [][]string{{"game/mc-a", "game/mc-b"}, {"game/mc-b", "game/mc-a"}} {
		rt := NewRouteTable()
		for _, key := range order {
			rt.Upsert(key, []string{"shared.uniz.host"}, b1Backend(key, 30001))
		}
		rt.Remove("game/mc-a")

		b, ok := rt.ByHost("shared.uniz.host")
		require.True(t, ok, order)
		assert.Equal(t, "game/mc-b", b.ServerID, order, "the next claimant takes over")
		b, ok = rt.ByLegacyPort(30001)
		require.True(t, ok, order)
		assert.Equal(t, "game/mc-b", b.ServerID, order)

		rt.Remove("game/mc-b")
		_, ok = rt.ByHost("shared.uniz.host")
		assert.False(t, ok, order)
		_, ok = rt.ByLegacyPort(30001)
		assert.False(t, ok, order)
	}
}
