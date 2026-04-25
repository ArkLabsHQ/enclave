package supervisor

import (
	"reflect"
	"testing"
)

func TestParseForwardPorts(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    map[string]string
		wantErr bool
	}{
		{
			name: "empty",
			spec: "",
			want: map[string]string{},
		},
		{
			name: "single same-port",
			spec: "7073",
			want: map[string]string{":7073": gvproxyVMIP + ":7073"},
		},
		{
			name: "multiple same-port",
			spec: "443 7073 9090",
			want: map[string]string{
				":443":  gvproxyVMIP + ":443",
				":7073": gvproxyVMIP + ":7073",
				":9090": gvproxyVMIP + ":9090",
			},
		},
		{
			name: "asymmetric host:vm",
			spec: "8443:443",
			want: map[string]string{":8443": gvproxyVMIP + ":443"},
		},
		{
			name: "mixed — test harness use case",
			spec: "8443:443 7073 9090",
			want: map[string]string{
				":8443": gvproxyVMIP + ":443",
				":7073": gvproxyVMIP + ":7073",
				":9090": gvproxyVMIP + ":9090",
			},
		},
		{
			name:    "invalid host port",
			spec:    "abc:443",
			wantErr: true,
		},
		{
			name:    "invalid vm port",
			spec:    "443:xyz",
			wantErr: true,
		},
		{
			name: "whitespace-only noise is ignored",
			spec: "  7073   ",
			want: map[string]string{":7073": gvproxyVMIP + ":7073"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseForwardPorts(tc.spec)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (result: %v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
