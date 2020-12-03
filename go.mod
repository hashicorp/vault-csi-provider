module github.com/hashicorp/secrets-store-csi-driver-provider-vault

go 1.12

require (
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/pflag v1.0.5
	golang.org/x/net v0.0.0-20200707034311-ab3426394381
	google.golang.org/grpc v1.27.1
	gopkg.in/yaml.v2 v2.3.0
	sigs.k8s.io/secrets-store-csi-driver v0.0.17
)
