package nginx

import "testing"

func TestServerTokensSetting(t *testing.T) {
	cases := []struct {
		name   string
		config string
		want   string
	}{
		{name: "off", config: "http { server_tokens off; }", want: "off"},
		{name: "on overrides", config: "http {\nserver_tokens off;\nserver {\nserver_tokens on;\n}\n}", want: "on"},
		{name: "comment ignored", config: "# server_tokens off;\nhttp { }", want: "default"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := serverTokensSetting(tc.config); got != tc.want {
				t.Fatalf("expected %s, got %s", tc.want, got)
			}
		})
	}
}
