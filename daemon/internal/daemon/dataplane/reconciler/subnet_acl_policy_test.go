package reconciler

import (
	juneau "github.com/1outres/juneau/controller/api/v1alpha1"
	"testing"
)

func TestSubnetACLIDFailsClosedWhileReferenceIsUnresolved(t *testing.T) {
	for _, tc := range []struct {
		name   string
		subnet juneau.Subnet
		want   uint32
	}{
		{name: "no ACL", subnet: juneau.Subnet{}, want: 0},
		{name: "resolved ACL", subnet: juneau.Subnet{Spec: juneau.SubnetSpec{NetworkACL: "restricted"}, Status: juneau.SubnetStatus{NetworkACL: &juneau.NetworkACLRef{Name: "restricted", ACLID: 42}}}, want: 42},
		{name: "new ACL not yet in status", subnet: juneau.Subnet{Spec: juneau.SubnetSpec{NetworkACL: "restricted"}}, want: pendingACLID},
		{name: "new ACL has no ID", subnet: juneau.Subnet{Spec: juneau.SubnetSpec{NetworkACL: "restricted"}, Status: juneau.SubnetStatus{NetworkACL: &juneau.NetworkACLRef{Name: "restricted"}}}, want: pendingACLID},
		{name: "old ACL still in status", subnet: juneau.Subnet{Spec: juneau.SubnetSpec{NetworkACL: "new"}, Status: juneau.SubnetStatus{NetworkACL: &juneau.NetworkACLRef{Name: "old", ACLID: 41}}}, want: pendingACLID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := subnetACLID(&tc.subnet); got != tc.want {
				t.Fatalf("aclID = %d, want %d", got, tc.want)
			}
		})
	}
}
