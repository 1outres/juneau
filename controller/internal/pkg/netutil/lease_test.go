package netutil

import "testing"

func TestLeaseNameFor(t *testing.T) {
	tests := []struct {
		name    string
		subnet  string
		address string
		want    string
	}{
		{
			name:    "standard IPv4 address",
			subnet:  "subnet-1",
			address: "192.168.1.10",
			want:    "subnet-1-192-168-1-10",
		},
		{
			name:    "first IP in subnet",
			subnet:  "my-subnet",
			address: "10.0.0.1",
			want:    "my-subnet-10-0-0-1",
		},
		{
			name:    "last IP in /24",
			subnet:  "test-subnet",
			address: "172.16.0.254",
			want:    "test-subnet-172-16-0-254",
		},
		{
			name:    "subnet with dashes",
			subnet:  "my-test-subnet",
			address: "192.168.100.50",
			want:    "my-test-subnet-192-168-100-50",
		},
		{
			name:    "zero address",
			subnet:  "subnet",
			address: "0.0.0.0",
			want:    "subnet-0-0-0-0",
		},
		{
			name:    "broadcast-like address",
			subnet:  "subnet",
			address: "255.255.255.255",
			want:    "subnet-255-255-255-255",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LeaseNameFor(tt.subnet, tt.address); got != tt.want {
				t.Errorf("LeaseNameFor() = %v, want %v", got, tt.want)
			}
		})
	}
}
