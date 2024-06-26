package starboard

import (
	"github.com/khulnasoft/starboard-khulnasoft-csp-webhook/pkg/etc"
	sec "github.com/khulnasoft/starboard/pkg/apis/khulnasoft/v1alpha1"
	clientset "github.com/khulnasoft/starboard/pkg/generated/clientset/versioned"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/errors"
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
	vulnerability, err := s.client.KhulnasoftV1alpha1().Vulnerabilities(s.config.Namespace).Get(name, meta.GetOptions{})
	if err != nil && errors.IsNotFound(err) {
		log.WithField("name", name).Debug("Creating vulnerabilities report")
		_, err = s.client.KhulnasoftV1alpha1().Vulnerabilities(s.config.Namespace).Create(&sec.Vulnerability{
			ObjectMeta: meta.ObjectMeta{
				Name: name,
			},
			Report: report,
		})
		return
	}
	if err != nil {
		return
	}
	copied := vulnerability.DeepCopy()
	copied.Report = report

	log.WithField("name", name).Debug("Updating vulnerabilities report")
	_, err = s.client.KhulnasoftV1alpha1().Vulnerabilities(s.config.Namespace).Update(copied)

	return
}
