package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/aquasecurity/starboard-aqua-csp-webhook/pkg/aqua"
	"github.com/aquasecurity/starboard-aqua-csp-webhook/pkg/starboard"
	log "github.com/sirupsen/logrus"
)

type handler struct {
	converter starboard.Converter
	writer    starboard.Writer
}

func NewHandler(converter starboard.Converter, writer starboard.Writer) http.Handler {
	handler := &handler{
		converter: converter,
		writer:    writer,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", handler.acceptScanReport)
	return mux
}

func (h *handler) acceptScanReport(w http.ResponseWriter, r *http.Request) {
	log.Debugf("Request URL: %s %s", r.Method, r.URL.String())
	log.Debugf("Request Headers: %v", r.Header)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var report aqua.ScanReport
	err := json.NewDecoder(r.Body).Decode(&report)
	defer func() {
		_ = r.Body.Close()
	}()
	if err != nil {
		log.Errorf("Error while decoding scan report: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	log.Debugf("Scan Digest: %s", report.Digest)
	log.Debugf("Scan Image: %s", report.Image)
	log.Debugf("Scan PullName: %s", report.PullName)
	log.Debugf("Scan Summary: %+v", report.Summary)
	log.Debugf("Scan Options: %+v", report.ScanOptions)

	err = h.save(report)
	if err != nil {
		log.Errorf("Error while saving vulnerabilities report to CR: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *handler) save(aquaReport aqua.ScanReport) (err error) {
	starboardReport := h.converter.Convert(aquaReport)
	err = h.writer.Write(strings.Replace(aquaReport.Digest, ":", ".", 1), starboardReport)
	if err != nil {
		return
	}
	return
}
