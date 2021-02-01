module github.com/hashicorp/secrets-store-csi-driver-provider-vault

go 1.12

require (
	github.com/hashicorp/go-hclog v0.8.0
	github.com/hashicorp/vault/api v1.0.4
	github.com/mitchellh/mapstructure v1.4.1
	github.com/pkg/errors v0.9.1
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.6.1
	golang.org/x/net v0.0.0-20200707034311-ab3426394381
	google.golang.org/grpc v1.27.1
	gopkg.in/yaml.v2 v2.3.0
	gopkg.in/yaml.v3 v3.0.0-20200605160147-a5ece683394c // indirect
	gotest.tools v2.2.0+incompatible
	sigs.k8s.io/secrets-store-csi-driver v0.0.17
)
