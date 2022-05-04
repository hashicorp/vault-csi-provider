module github.com/hashicorp/vault-csi-provider

go 1.13

require (
	github.com/hashicorp/go-hclog v1.0.0
	github.com/hashicorp/vault/api v1.2.0
	github.com/hashicorp/yamux v0.0.0-20181012175058-2f1d1f20f75d // indirect
	github.com/stretchr/testify v1.7.0
	google.golang.org/grpc v1.41.0
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
	k8s.io/api v0.22.2
	k8s.io/apimachinery v0.22.2
	k8s.io/client-go v0.22.2
	sigs.k8s.io/secrets-store-csi-driver v1.0.0
)
