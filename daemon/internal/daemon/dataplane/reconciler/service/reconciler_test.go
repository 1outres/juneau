package service

import "testing"

// TestRemoveSnapshot_DropsKey ensures the bookkeeping helper actually
// drops the entry. The Reconciler.delete path relies on this so that
// deleted Services don't leak snapshots indefinitely under Service
// churn.
func TestRemoveSnapshot_DropsKey(t *testing.T) {
	r := &Reconciler{snapshots: make(map[string]programSnapshot)}
	r.storeSnapshot("ns/a", programSnapshot{gen: 1})
	r.storeSnapshot("ns/b", programSnapshot{gen: 2})

	r.removeSnapshot("ns/a")

	if _, ok := r.snapshots["ns/a"]; ok {
		t.Errorf("snapshot ns/a still present after removeSnapshot")
	}
	if _, ok := r.snapshots["ns/b"]; !ok {
		t.Errorf("removeSnapshot must not affect unrelated keys")
	}
}

func TestRemoveSnapshot_NoOpOnMissingKey(t *testing.T) {
	r := &Reconciler{snapshots: make(map[string]programSnapshot)}
	r.removeSnapshot("ns/missing")
	if got := len(r.snapshots); got != 0 {
		t.Errorf("removeSnapshot on missing key must not insert; got %d entries", got)
	}
}
