// Copyright 2019 Sonatype Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package output implements ouputting the audit to different targets.
package output

import (
	"encoding/xml"
	"fmt"
	"os"
	"time"

	"github.com/sonatype-nexus-community/nancy/audit"
	"github.com/sonatype-nexus-community/nancy/types"
)

// AuditOutputter is an interface specifying a method that can be used to output audit results
type AuditOutputter interface {
	// TODO: Return err instead and have another mechanism for getting vuln count
	LogResults(packageCount int, coordinates []types.Coordinate, exclusions []string) int
}

// ConsoleOutputter is a type that implements the AuditOutputter interface and outputs to the console
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
func (o *ConsoleOutputter) LogResults(packageCount int, coordinates []types.Coordinate, exclusions []string) int {
	return audit.LogResults(o.NoColor, o.Quiet, packageCount, coordinates, exclusions)
}

// JUnitOutputter is a type that implements the AuditOutputter and outputs a JUnit XML report
type JUnitOutputter struct {
	Path string
	Name string
}

// NewJUnitOutputter creates a new JUnitOutputter
func NewJUnitOutputter(name, path string) *JUnitOutputter {
	return &JUnitOutputter{
		Path: path, // TODO: Change to io.Writer?
		Name: name,
	}
}

// JUnitReport is a JUnit test suites report.
type JUnitReport struct {
	XMLName    xml.Name         `xml:"testsuites"`
	Text       string           `xml:",chardata"`
	ID         string           `xml:"id,attr"`
	Name       string           `xml:"name,attr"`
	Tests      int              `xml:"tests,attr"`
	Failures   int              `xml:"failures,attr"`
	Time       string           `xml:"time,attr"`
	TestSuites []JUnitTestSuite `xml:"testsuite"`
}

type JUnitTestSuite struct {
	Text      string          `xml:",chardata"`
	ID        string          `xml:"id,attr"`
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Time      string          `xml:"time,attr"`
	TestCases []JUnitTestCase `xml:"testcase"`
}

// JUnitTestCase is a JUnit test case description.
type JUnitTestCase struct {
	Text        string            `xml:",chardata"`
	ID          string            `xml:"id,attr"`
	Name        string            `xml:"name,attr"`
	Time        string            `xml:"time,attr"`
	Failures    []JUnitFailure    `xml:"failure,omitempty"`
	SkipMessage *JUnitSkipMessage `xml:"skipped,omitempty"`
}

// JUnitFailure is a JUnit test case failure description.
type JUnitFailure struct {
	Text    string `xml:",chardata"`
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
}

// JUnitSkipMessage is a JUnit skip message.
type JUnitSkipMessage struct {
	Message string `xml:"message,attr"`
}

func (o *JUnitOutputter) LogResults(packageCount int, coordinates []types.Coordinate, exclusions []string) int {
	vulnerableCount := 0
	testSuite := JUnitTestSuite{
		Name:      "Golang dependency vulnerability report",
		TestCases: make([]JUnitTestCase, len(coordinates)),
	}

	// TODO: This should be done outside the output code!
	// Loops through and marks any vulnerabilities as excluded in the list of coordinates.
	// (But the vulnerabilities are still available)
	for _, c := range coordinates {
		c.ExcludeVulnerabilities(exclusions)
	}

	for i := 0; i < len(coordinates); i++ {
		c := coordinates[i]

		testCase := JUnitTestCase{
			Name:     c.Coordinates,
			Text:     c.Reference,
			Failures: []JUnitFailure{},
			Time:     time.Now().Format(time.RFC3339),
		}

		packageIsVulnerable := false

		for _, v := range c.Vulnerabilities {
			if !v.Excluded {
				testCase.Failures = append(testCase.Failures, JUnitFailure{
					Type:    "ERROR",
					Message: v.Title,
					Text: fmt.Sprintf("\n%s\n%s\n\nID:%s\nDetails:%s",
						v.Title,
						v.Description,
						v.Id,
						v.Reference),
				})
				packageIsVulnerable = true
			}
		}

		// We only count which packages are vulnerable.
		// Not how many, if more than one that packages has.
		if packageIsVulnerable {
			vulnerableCount++
		}

		testSuite.TestCases[i] = testCase
	}

	report := JUnitReport{
		Name:       o.Name,
		TestSuites: []JUnitTestSuite{testSuite},
		Tests:      len(testSuite.TestCases),
		Failures:   vulnerableCount,
	}

	bytes, err := xml.MarshalIndent(report, "", "    ")
	if err != nil {
		return 1
	}

	os.Stdout.Write(bytes)

	return vulnerableCount
}
