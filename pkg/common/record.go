package common

type Record struct {
	Type    string
	Name    string
	Target  string
	TTL     int
	Proxied bool
}
