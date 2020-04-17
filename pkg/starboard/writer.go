package starboard

import (
	sec "github.com/aquasecurity/k8s-security-crds/pkg/apis/aquasecurity/v1alpha1"
	clientset "github.com/aquasecurity/k8s-security-crds/pkg/generated/clientset/versioned"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Writer struct {
	client clientset.Interface
}

func NewWriter(client clientset.Interface) *Writer {
	return &Writer{
		client: client,
	}
}

func (s *Writer) Write(name string, report sec.VulnerabilityReport) (err error) {
	_, err = s.client.AquasecurityV1alpha1().Vulnerabilities("starboard").Create(&sec.Vulnerability{
		ObjectMeta: meta.ObjectMeta{
			Name: name,
		},
		Report: report,
	})
	return
}
