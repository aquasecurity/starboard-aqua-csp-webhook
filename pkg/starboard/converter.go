package starboard

import (
	"github.com/aquasecurity/starboard-aqua-csp-webhook/pkg/ext"

	security "github.com/aquasecurity/k8s-security-crds/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard-aqua-csp-webhook/pkg/aqua"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Converter interface {
	Convert(aquaReport aqua.ScanReport) security.VulnerabilityReport
}

func NewConverter(clock ext.Clock) Converter {
	return &converter{
		clock: clock,
	}
}

type converter struct {
	clock ext.Clock
}

func (c *converter) Convert(aquaReport aqua.ScanReport) (starboardReport security.VulnerabilityReport) {
	var items []security.VulnerabilityItem

	for _, resourceScan := range aquaReport.Resources {
		for _, vln := range resourceScan.Vulnerabilities {
			log.WithFields(log.Fields{
				"name": resourceScan.Resource.Name,
				"path": resourceScan.Resource.Path,
				"type": resourceScan.Resource.Type,
			}).Trace("Resource")
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
				pkg = resourceScan.Resource.Name
			}
			items = append(items, security.VulnerabilityItem{
				VulnerabilityID:  vln.Name,
				Resource:         pkg,
				InstalledVersion: resourceScan.Resource.Version,
				FixedVersion:     vln.FixVersion,
				Severity:         c.toSeverity(vln),
				Description:      vln.Description,
				Links:            c.toLinks(vln),
			})
		}
	}
	starboardReport = security.VulnerabilityReport{
		GeneratedAt:     metav1.NewTime(c.clock.Now()),
		Vulnerabilities: items,
		Scanner: security.Scanner{
			Name:   "Aqua CSP",
			Vendor: "Aqua Security",
		},
		Summary: c.toSummary(aquaReport.Summary),
	}

	return
}

func (c *converter) toSeverity(v aqua.Vulnerability) security.Severity {
	switch severity := v.AquaSeverity; severity {
	case "critical":
		return security.SeverityCritical
	case "high":
		return security.SeverityHigh
	case "medium":
		return security.SeverityMedium
	case "low":
		return security.SeverityLow
	case "negligible":
		// TODO We should have severity None defined in k8s-security-crds
		return security.SeverityUnknown
	default:
		log.WithField("severity", severity).Warn("Unknown Aqua severity")
		return security.SeverityUnknown
	}
}

func (c *converter) toLinks(v aqua.Vulnerability) []string {
	var links []string
	if v.NVDURL != "" {
		links = append(links, v.NVDURL)
	}
	if v.VendorURL != "" {
		links = append(links, v.VendorURL)
	}
	return links
}

func (c *converter) toSummary(aquaSummary aqua.VulnerabilitySummary) security.VulnerabilitySummary {
	return security.VulnerabilitySummary{
		CriticalCount: aquaSummary.Critical,
		HighCount:     aquaSummary.High,
		MediumCount:   aquaSummary.Medium,
		LowCount:      aquaSummary.Low,
	}
}
