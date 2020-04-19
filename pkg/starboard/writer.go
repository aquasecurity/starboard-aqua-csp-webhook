package starboard

import (
	sec "github.com/aquasecurity/k8s-security-crds/pkg/apis/aquasecurity/v1alpha1"
	clientset "github.com/aquasecurity/k8s-security-crds/pkg/generated/clientset/versioned"
	"github.com/aquasecurity/starboard-aqua-csp-webhook/pkg/etc"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Writer interface {
	Write(name string, report sec.VulnerabilityReport) (err error)
}

type writer struct {
	config etc.Starboard
	client clientset.Interface
}

func NewWriter(config etc.Starboard, client clientset.Interface) Writer {
	return &writer{
		config: config,
		client: client,
	}
}

func (s *writer) Write(name string, report sec.VulnerabilityReport) (err error) {
	_, err = s.client.AquasecurityV1alpha1().Vulnerabilities(s.config.Namespace).Create(&sec.Vulnerability{
		ObjectMeta: meta.ObjectMeta{
			Name: name,
		},
		Report: report,
	})
	return
}
