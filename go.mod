module container-dns-companion

go 1.23.0

toolchain go1.24.2

require (
	github.com/cloudflare/cloudflare-go v0.115.0
	github.com/docker/docker v24.0.6+incompatible
	golang.org/x/exp v0.0.0-20250506013437-ce4c2cf36ca6
	gopkg.in/yaml.v3 v3.0.1
)

// This replace directive tells Go to use the local module code
// when any imports reference the GitHub repository
replace github.com/nfrastack/container-dns-companion => ./

require (
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/docker/distribution v2.8.2+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/moby/term v0.5.2 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/mod v0.24.0 // indirect
	golang.org/x/net v0.40.0 // indirect
	golang.org/x/sync v0.14.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.25.0 // indirect
	golang.org/x/time v0.11.0 // indirect
	golang.org/x/tools v0.33.0 // indirect
	gotest.tools/v3 v3.5.2 // indirect
)
