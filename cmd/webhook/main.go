package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	secapi "github.com/aquasecurity/k8s-security-crds/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/starboard-aqua-csp-webhook/pkg/aqua"
	"github.com/aquasecurity/starboard-aqua-csp-webhook/pkg/starboard"
	"k8s.io/client-go/rest"
)

func main() {
	log.SetLevel(log.DebugLevel)
	if err := run(os.Args); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func run(_ []string) (err error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", acceptScanReport)
	log.Info("Starting server on :4000")
	err = http.ListenAndServe(":4000", mux)
	return
}

func acceptScanReport(w http.ResponseWriter, r *http.Request) {
	log.Debugf("Request URL: %s %s", r.Method, r.URL.String())
	log.Debugf("Request Headers: %v", r.Header)

	var report aqua.ScanReport
	err := json.NewDecoder(r.Body).Decode(&report)
	if err != nil {
		log.Errorf("Error: %v", err)
	}
	defer func() {
		_ = r.Body.Close()
	}()

	log.Debugf("Scan Digest: %s", report.Digest)
	log.Debugf("Scan Image: %s", report.Image)
	log.Debugf("Scan PullName: %s", report.PullName)
	log.Debugf("Scan summary: %+v", report.VulnerabilitySummary)
	log.Debugf("Scan options: %+v", report.ScanOptions)

	err = save(report)
	if err != nil {
		log.Error("Error while saving vulnerabilities report to CR: %w", err)
	}

	w.WriteHeader(http.StatusOK)
}

func save(report aqua.ScanReport) (err error) {
	sr := starboard.FromAquaScanReport(report)

	cfg, err := rest.InClusterConfig()
	if err != nil {
		return
	}
	clientset, err := secapi.NewForConfig(cfg)
	if err != nil {
		return
	}

	writer := starboard.NewWriter(clientset)
	err = writer.Write(strings.Replace(report.Digest, ":", ".", 1), sr)
	if err != nil {
		return
	}

	return
}
