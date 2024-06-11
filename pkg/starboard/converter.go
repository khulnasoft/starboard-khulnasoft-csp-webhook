package starboard

import (
	"github.com/khulnasoft/starboard-khulnasoft-csp-webhook/pkg/ext"

	"github.com/khulnasoft/starboard-khulnasoft-csp-webhook/pkg/khulnasoft"
	starboard "github.com/khulnasoft/starboard/pkg/apis/khulnasoft/v1alpha1"
	log "github.com/sirupsen/logrus"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Converter interface {
	Convert(khulnasoftReport khulnasoft.ScanReport) starboard.VulnerabilityReport
}

func NewConverter(clock ext.Clock) Converter {
	return &converter{
		clock: clock,
	}
}

type converter struct {
	clock ext.Clock
}

func (c *converter) Convert(khulnasoftReport khulnasoft.ScanReport) (starboardReport starboard.VulnerabilityReport) {
	var items []starboard.VulnerabilityItem

	for _, resourceScan := range khulnasoftReport.Resources {
		for _, vln := range resourceScan.Vulnerabilities {
			log.WithFields(log.Fields{
				"name": resourceScan.Resource.Name,
				"path": resourceScan.Resource.Path,
				"type": resourceScan.Resource.Type,
			}).Trace("Resource")
			var pkg string
			switch resourceScan.Resource.Type {
			case khulnasoft.Library:
				pkg = resourceScan.Resource.Path
			case khulnasoft.Package:
				pkg = resourceScan.Resource.Name
			default:
				log.WithFields(log.Fields{
					"resource_name": resourceScan.Resource.Name,
					"resource_path": resourceScan.Resource.Path,
					"resource_type": resourceScan.Resource.Type,
				}).Warn("Unknown resource type")
				pkg = resourceScan.Resource.Name
			}
			items = append(items, starboard.VulnerabilityItem{
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
	starboardReport = starboard.VulnerabilityReport{
		GeneratedAt:     meta.NewTime(c.clock.Now()),
		Vulnerabilities: items,
		Scanner: starboard.Scanner{
			Name:   "Khulnasoft CSP",
			Vendor: "Khulnasoft Security",
		},
		Summary: c.toSummary(khulnasoftReport.Summary),
	}

	return
}

func (c *converter) toSeverity(v khulnasoft.Vulnerability) starboard.Severity {
	switch severity := v.KhulnasoftSeverity; severity {
	case "critical":
		return starboard.SeverityCritical
	case "high":
		return starboard.SeverityHigh
	case "medium":
		return starboard.SeverityMedium
	case "low":
		return starboard.SeverityLow
	case "negligible":
		// TODO We should have severity None defined in k8s-security-crds
		return starboard.SeverityUnknown
	default:
		log.WithField("severity", severity).Warn("Unknown Khulnasoft severity")
		return starboard.SeverityUnknown
	}
}

func (c *converter) toLinks(v khulnasoft.Vulnerability) []string {
	var links []string
	if v.NVDURL != "" {
		links = append(links, v.NVDURL)
	}
	if v.VendorURL != "" {
		links = append(links, v.VendorURL)
	}
	return links
}

func (c *converter) toSummary(khulnasoftSummary khulnasoft.VulnerabilitySummary) starboard.VulnerabilitySummary {
	return starboard.VulnerabilitySummary{
		CriticalCount: khulnasoftSummary.Critical,
		HighCount:     khulnasoftSummary.High,
		MediumCount:   khulnasoftSummary.Medium,
		LowCount:      khulnasoftSummary.Low,
	}
}
