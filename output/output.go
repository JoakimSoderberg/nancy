package output

import (
	"github.com/sonatype-nexus-community/nancy/audit"
	"github.com/sonatype-nexus-community/nancy/types"
)

// AuditOutputter is an interface specifying a method that can be used to output audit results
type AuditOutputter interface {
	LogResults(packageCount int, coordinates []types.Coordinate, exclusions []string) int
}

// ConsoleOutputter is a type that implements the AuditOutputter interface.
type ConsoleOutputter struct {
	NoColor bool
	Quiet   bool
}

// NewConsoleOutputter creates a new ConsoleOutputter that can be used to output the audit results to console.
func NewConsoleOutputter(noColor, quiet bool) *ConsoleOutputter {
	return &ConsoleOutputter{
		NoColor: noColor,
		Quiet:   quiet,
	}
}

// LogResults outputs the audit results to console.
func (c *ConsoleOutputter) LogResults(packageCount int, coordinates []types.Coordinate, exclusions []string) int {
	return audit.LogResults(c.NoColor, c.Quiet, packageCount, coordinates, exclusions)
}
