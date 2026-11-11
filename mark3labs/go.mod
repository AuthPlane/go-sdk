module github.com/authplane/go-sdk/mark3labs

go 1.26.0

toolchain go1.27.3

require (
	github.com/authplane/go-sdk/core v0.0.0
	github.com/authplane/go-sdk/http v0.0.0
	github.com/go-jose/go-jose/v4 v4.1.9
	github.com/mark3labs/mcp-go v1.5.0
)

require (
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/text v0.43.0 // indirect
)

replace (
	github.com/authplane/go-sdk/core => ../core
	github.com/authplane/go-sdk/http => ../http
)
