package output

import (
	"testing"

	decimal "github.com/shopspring/decimal"
	"github.com/sonatype-nexus-community/nancy/types"
)

func TestEmptyConsoleOutputter(t *testing.T) {
	//purl := "pkg:github/BurntSushi/toml@0.3.1"

	o := NewConsoleOutputter(false, false)
	o.LogResults(0, []types.Coordinate{}, []string{})
}

func TestLogVulnConsoleOutputter(t *testing.T) {

	coords := []types.Coordinate{
		{
			Coordinates: "",
			Reference:   "Made up",
			Vulnerabilities: []types.Vulnerability{
				{
					Id:          "123",
					Title:       "The bug",
					Description: "This is so bad",
					CvssScore:   decimal.Decimal{},
					CvssVector:  "Oh noes",
					Cve:         "CVE0001",
					Reference:   "https://example.com",
					Excluded:    false,
				},
			},
		},
	}

	// TODO: If we make the audit code use a wrapper for stdout ouput we can assert on the output
	o := NewConsoleOutputter(false, false)
	o.LogResults(1, coords, []string{})
}
