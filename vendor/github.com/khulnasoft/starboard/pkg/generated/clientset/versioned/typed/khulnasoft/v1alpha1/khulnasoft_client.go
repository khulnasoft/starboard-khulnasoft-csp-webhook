// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "github.com/khulnasoft/starboard/pkg/apis/khulnasoft/v1alpha1"
	"github.com/khulnasoft/starboard/pkg/generated/clientset/versioned/scheme"
	rest "k8s.io/client-go/rest"
)

type KhulnasoftV1alpha1Interface interface {
	RESTClient() rest.Interface
	CISKubeBenchReportsGetter
	ConfigAuditReportsGetter
	KubeHunterReportsGetter
	VulnerabilityReportsGetter
}

// KhulnasoftV1alpha1Client is used to interact with features provided by the khulnasoft.github.io group.
type KhulnasoftV1alpha1Client struct {
	restClient rest.Interface
}

func (c *KhulnasoftV1alpha1Client) CISKubeBenchReports() CISKubeBenchReportInterface {
	return newCISKubeBenchReports(c)
}

func (c *KhulnasoftV1alpha1Client) ConfigAuditReports(namespace string) ConfigAuditReportInterface {
	return newConfigAuditReports(c, namespace)
}

func (c *KhulnasoftV1alpha1Client) KubeHunterReports() KubeHunterReportInterface {
	return newKubeHunterReports(c)
}

func (c *KhulnasoftV1alpha1Client) VulnerabilityReports(namespace string) VulnerabilityReportInterface {
	return newVulnerabilityReports(c, namespace)
}

// NewForConfig creates a new KhulnasoftV1alpha1Client for the given config.
func NewForConfig(c *rest.Config) (*KhulnasoftV1alpha1Client, error) {
	config := *c
	if err := setConfigDefaults(&config); err != nil {
		return nil, err
	}
	client, err := rest.RESTClientFor(&config)
	if err != nil {
		return nil, err
	}
	return &KhulnasoftV1alpha1Client{client}, nil
}

// NewForConfigOrDie creates a new KhulnasoftV1alpha1Client for the given config and
// panics if there is an error in the config.
func NewForConfigOrDie(c *rest.Config) *KhulnasoftV1alpha1Client {
	client, err := NewForConfig(c)
	if err != nil {
		panic(err)
	}
	return client
}

// New creates a new KhulnasoftV1alpha1Client for the given RESTClient.
func New(c rest.Interface) *KhulnasoftV1alpha1Client {
	return &KhulnasoftV1alpha1Client{c}
}

func setConfigDefaults(config *rest.Config) error {
	gv := v1alpha1.SchemeGroupVersion
	config.GroupVersion = &gv
	config.APIPath = "/apis"
	config.NegotiatedSerializer = scheme.Codecs.WithoutConversion()

	if config.UserAgent == "" {
		config.UserAgent = rest.DefaultKubernetesUserAgent()
	}

	return nil
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *KhulnasoftV1alpha1Client) RESTClient() rest.Interface {
	if c == nil {
		return nil
	}
	return c.restClient
}
