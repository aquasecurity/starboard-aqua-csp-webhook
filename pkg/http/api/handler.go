package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/aquasecurity/starboard-aqua-csp-webhook/pkg/aqua"
	"github.com/aquasecurity/starboard-aqua-csp-webhook/pkg/starboard"
	log "github.com/sirupsen/logrus"
)

type Handler struct {
	writer *starboard.Writer
}

func NewHandler(writer *starboard.Writer) *Handler {
	return &Handler{
		writer: writer,
	}
}

func (h *Handler) AcceptScanReport(w http.ResponseWriter, r *http.Request) {
	log.Debugf("Request URL: %s %s", r.Method, r.URL.String())
	log.Debugf("Request Headers: %v", r.Header)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method Not Allowed", 405)
		return
	}

	var report aqua.ScanReport
	err := json.NewDecoder(r.Body).Decode(&report)
	if err != nil {
		// TODO Unprocessable entity
		log.Errorf("Error: %v", err)
	}
	defer func() {
		_ = r.Body.Close()
	}()

	log.Debugf("Scan Digest: %s", report.Digest)
	log.Debugf("Scan Image: %s", report.Image)
	log.Debugf("Scan PullName: %s", report.PullName)
	log.Debugf("Scan Summary: %+v", report.Summary)
	log.Debugf("Scan Options: %+v", report.ScanOptions)

	err = h.save(report)
	if err != nil {
		log.Error("Error while saving vulnerabilities report to CR: %w", err)
	}

	w.WriteHeader(http.StatusOK)
}

func (h *Handler) save(report aqua.ScanReport) (err error) {
	sr := starboard.FromAquaScanReport(report)
	err = h.writer.Write(strings.Replace(report.Digest, ":", ".", 1), sr)
	if err != nil {
		return
	}

	return
}
