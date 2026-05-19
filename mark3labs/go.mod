module github.com/authplane/go-sdk/mark3labs

go 1.25.5

require (
	github.com/authplane/go-sdk/core v0.0.0
	github.com/go-jose/go-jose/v4 v4.1.3
	github.com/mark3labs/mcp-go v0.54.0
)

require (
	github.com/google/jsonschema-go v0.4.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2 // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/text v0.14.0 // indirect
)

replace github.com/authplane/go-sdk/core => ../core
