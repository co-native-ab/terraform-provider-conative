// Command terraform-provider-conative serves the conative Terraform provider.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/co-native-ab/terraform-provider-conative/internal/provider"
)

// Regenerate the documentation under docs/ from the schemas, examples/ and templates/.
//go:generate go tool -modfile=tools/go.mod tfplugindocs generate --provider-name conative

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with support for debuggers such as delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/co-native-ab/conative",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err.Error())
	}
}
