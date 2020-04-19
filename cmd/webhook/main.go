package main

import (
	"github.com/aquasecurity/starboard-aqua-csp-webhook/pkg/ext"
	"net/http"
	"os"

	"github.com/aquasecurity/starboard-aqua-csp-webhook/pkg/etc"

	"github.com/aquasecurity/starboard-aqua-csp-webhook/pkg/starboard"
	"k8s.io/client-go/rest"

	secapi "github.com/aquasecurity/k8s-security-crds/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/starboard-aqua-csp-webhook/pkg/http/api"
	log "github.com/sirupsen/logrus"
)

func main() {
	log.SetLevel(log.DebugLevel)
	if err := run(os.Args); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func run(_ []string) (err error) {
	config, err := etc.GetConfig()
	if err != nil {
		return
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return
	}
	clientset, err := secapi.NewForConfig(cfg)
	if err != nil {
		return
	}

	converter := starboard.NewConverter(ext.SystemClock)
	writer := starboard.NewWriter(config.Starboard, clientset)
	handler := api.NewHandler(converter, writer)
	log.Infof("Starting server on %s", config.API.Addr)
	err = http.ListenAndServe(config.API.Addr, handler)
	return
}
