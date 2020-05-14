package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/aquasecurity/starboard-aqua-csp-webhook/pkg/ext"

	"github.com/aquasecurity/starboard-aqua-csp-webhook/pkg/etc"

	"github.com/aquasecurity/starboard-aqua-csp-webhook/pkg/starboard"
	"k8s.io/client-go/rest"

	"github.com/aquasecurity/starboard-aqua-csp-webhook/pkg/http/api"
	starboardapi "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	log "github.com/sirupsen/logrus"
)

func main() {
	log.SetLevel(etc.GetLogLevel())
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
	clientset, err := starboardapi.NewForConfig(cfg)
	if err != nil {
		return
	}

	converter := starboard.NewConverter(ext.SystemClock)
	writer := starboard.NewWriter(config.Starboard, clientset)
	handler := api.NewHandler(converter, writer)
	apiServer := api.NewServer(config.API, handler)

	complete := make(chan struct{})

	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, syscall.SIGINT, syscall.SIGTERM)
		captured := <-sigint
		log.WithField("signal", captured.String()).Trace("Trapped os signal")

		apiServer.Shutdown()

		close(complete)
	}()

	go func() {
		apiServer.ListenAndServe()
	}()

	<-complete
	return
}
