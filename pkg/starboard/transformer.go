package starboard

import (
	"time"

	security "github.com/aquasecurity/k8s-security-crds/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard-aqua-csp-webhook/pkg/aqua"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func FromAquaScanReport(source aqua.ScanReport) (starboardReport security.VulnerabilityReport) {
	var items []security.VulnerabilityItem

	for _, resourceScan := range source.Resources {
		for _, vln := range resourceScan.Vulnerabilities {
			var pkg string
			switch resourceScan.Resource.Type {
			case aqua.Library:
				pkg = resourceScan.Resource.Path
			case aqua.Package:
				pkg = resourceScan.Resource.Name
			default:
				log.WithFields(log.Fields{
					"resource_name": resourceScan.Resource.Name,
					"resource_path": resourceScan.Resource.Path,
					"resource_type": resourceScan.Resource.Type,
				}).Warn("Unknown resource type")
				pkg = resourceScan.Resource.Path
			}
			items = append(items, security.VulnerabilityItem{
				VulnerabilityID:  vln.Name,
				Resource:         pkg,
				InstalledVersion: resourceScan.Resource.Version,
				FixedVersion:     vln.FixVersion,
				Severity:         toSeverity(vln),
				Description:      vln.Description,
				Links:            toLinks(vln),
			})
		}
	}
	starboardReport = security.VulnerabilityReport{
		GeneratedAt:     v1.NewTime(time.Now()),
		Vulnerabilities: items,
		Scanner: security.Scanner{
			Name:   "Aqua CSP",
			Vendor: "Aqua Security",
		},
		Summary: toSummary(source.VulnerabilitySummary),
	}

	return
}

func toSeverity(_ aqua.Vulnerability) (severity security.Severity) {
	// TODO Implement me
	severity = security.SeverityCritical
	return
}

func toLinks(v aqua.Vulnerability) []string {
	var links []string
	if v.NVDURL != "" {
		links = append(links, v.NVDURL)
	}
	if v.VendorURL != "" {
		links = append(links, v.VendorURL)
	}
	return links
}

func toSummary(aquaSummary aqua.VulnerabilitySummary) security.VulnerabilitySummary {
	// TODO Implement me
	return security.VulnerabilitySummary{}
}
