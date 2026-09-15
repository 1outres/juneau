package mapinventory

import (
	"testing"

	"github.com/1outres/juneau/daemon/internal/daemon/dataplane/reconciler/ownedaddr"
)

// external_address_pools holds what ownedaddr.Store writes, so a dump has
// to name the values that type defines.
func TestExternalAddressDeliveryEnumNamesWhatTheStoreWrites(t *testing.T) {
	for delivery, want := range map[ownedaddr.Delivery]string{
		ownedaddr.DeliveredHere:      "EXTERNAL_ADDRESS_DELIVERED_HERE",
		ownedaddr.DeliveredElsewhere: "EXTERNAL_ADDRESS_DELIVERED_ELSEWHERE",
	} {
		if got := ExternalAddressDeliveryEnum.Render(uint64(delivery)); got != want {
			t.Errorf("%s renders as %q, want %q", delivery, got, want)
		}
	}
}
