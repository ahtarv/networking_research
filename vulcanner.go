package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const targetHost = "scanme.nmap.org"

type CVERecord struct {
	ID      string  `json:"id"`
	Summary string  `json:"summary"`
	CVSS    float64 `json:"cvss"`
}

type VulnerabilityResponse struct {
	Results struct {
		Nvd [][]interface{} `json:"nvd"`
	} `json:"results"`
}

func main() {
	fmt.Printf("Starting threat and vulnerability engine on: %s\n", targetHost)

	banner := grabBanner(targetHost, 22)

	if banner == "" {
		fmt.Println("Could not retrieve banner or port is closed")
		return
	}
	fmt.Printf("Raw banner captured: %s\n", banner)

	software, version := parseBanner(banner)

	if software == "" || version == "" {
		fmt.Println("Could not parse software version from banner")
		return
	}

	fmt.Printf("Parsed service target: product = '%s', version = '%s'\n\n", software, version)

	fmt.Println("Querying vulnerability intelligence database...")
	lookupVulnerabilities(software, version)
}

func grabBanner(host string, port int) string {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2*time.Second))

	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSpace(banner)
}

func parseBanner(banner string) (string, string) {
	if idx := strings.Index(banner, "OpenSSH_"); idx != -1 {
		versionPart := banner[idx+len("OpenSSH_"):]
		fields := strings.Fields(versionPart)
		if len(fields) > 0 {
			return "openssh", fields[0]
		}
	}
	return "", ""
}

func extractCvssFromMetrics(metrics []interface{}) float64 {
	for _, m := range metrics {
		mMap, ok := m.(map[string]interface{})
		if !ok {
			continue
		}
		for _, cvssKey := range []string{"cvssV3_1", "cvssV3_0", "cvssV2"} {
			if cvssObj, ok := mMap[cvssKey].(map[string]interface{}); ok {
				if score, ok := cvssObj["baseScore"].(float64); ok {
					return score
				}
			}
		}
	}
	return 0
}

func lookupVulnerabilities(product string, version string) {
	// Query the product search endpoint (vendor/product)
	api := fmt.Sprintf("https://cve.circl.lu/api/search/%s/%s", product, product)

	client := http.Client{
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequest("GET", api, nil)
	if err != nil {
		fmt.Printf("Error creating API request: %v\n", err)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("API query failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading API response: %v\n", err)
		return
	}

	var raw VulnerabilityResponse
	err = json.Unmarshal(body, &raw)
	if err != nil {
		fmt.Printf("Error parsing CVE response: %v\n", err)
		return
	}

	var cveData []CVERecord
	for _, pair := range raw.Results.Nvd {
		if len(pair) < 2 {
			continue
		}
		cveID, ok := pair[0].(string)
		if !ok {
			continue
		}

		detailMap, ok := pair[1].(map[string]interface{})
		if !ok {
			continue
		}

		var summary string
		if containers, ok := detailMap["containers"].(map[string]interface{}); ok {
			if cna, ok := containers["cna"].(map[string]interface{}); ok {
				if descriptions, ok := cna["descriptions"].([]interface{}); ok && len(descriptions) > 0 {
					if descMap, ok := descriptions[0].(map[string]interface{}); ok {
						if val, ok := descMap["value"].(string); ok {
							summary = val
						}
					}
				}
			}
		}

		var cvss float64
		if containers, ok := detailMap["containers"].(map[string]interface{}); ok {
			if cna, ok := containers["cna"].(map[string]interface{}); ok {
				if metrics, ok := cna["metrics"].([]interface{}); ok {
					cvss = extractCvssFromMetrics(metrics)
				}
			}
			if cvss == 0 {
				if adpList, ok := containers["adp"].([]interface{}); ok {
					for _, adpItem := range adpList {
						if adpMap, ok := adpItem.(map[string]interface{}); ok {
							if metrics, ok := adpMap["metrics"].([]interface{}); ok {
								cvss = extractCvssFromMetrics(metrics)
								if cvss > 0 {
									break
								}
							}
						}
					}
				}
			}
		}

		cveData = append(cveData, CVERecord{
			ID:      strings.ToUpper(cveID),
			Summary: summary,
			CVSS:    cvss,
		})
	}

	if len(cveData) == 0 {
		fmt.Println("No CVEs found for this service")
		return
	}

	// Filter and/or limit results
	// Let's filter CVEs that contain the version string in their summary if possible,
	// or fallback to the top CVEs if no version-specific ones match.
	var filteredCVEs []CVERecord
	for _, cve := range cveData {
		if strings.Contains(strings.ToLower(cve.Summary), strings.ToLower(version)) {
			filteredCVEs = append(filteredCVEs, cve)
		}
	}

	displayList := filteredCVEs
	if len(displayList) == 0 {
		// Fallback to top overall CVEs if version-specific search yielded nothing
		displayList = cveData
	}

	fmt.Printf("Found %d potential vulnerabilities (showing top match examples):\n\n", len(displayList))

	limit := 3
	if len(displayList) < limit {
		limit = len(displayList)
	}

	for i := 0; i < limit; i++ {
		cve := displayList[i]
		fmt.Printf("[%d] CVE ID: %s\n", i+1, cve.ID)
		if cve.CVSS > 0 {
			fmt.Printf("Severity score (CVSS): %.1f/10.0\n", cve.CVSS)
		}
		summary := cve.Summary
		if len(summary) > 120 {
			summary = summary[:117] + "..."
		}
		fmt.Printf("Summary: %s\n\n", summary)
	}
}