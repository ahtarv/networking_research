package main

import (
	"bufio"         // Used to read text lines from network sockets
	"encoding/json" // Used to translate JSON text into Go structures
	"fmt"           // Used for printing text to the console
	"io"            // Used for reading HTTP response streams
	"net"           // Used for networking (opening TCP sockets)
	"net/http"      // Used for making web API requests
	"strings"       // Used for text manipulation (splitting, matching strings)
	"time"          // Used for managing timeouts
)

// The target server we are testing
const targetHost = "scanme.nmap.org"

// CVERecord represents the clean, final CVE data we want to print to the console.
type CVERecord struct {
	ID      string  `json:"id"`
	Summary string  `json:"summary"`
	CVSS    float64 `json:"cvss"`
}

// VulnerabilityResponse maps the nested "results" structure returned by the CVE API.
// The API returns Nvd as a list of lists: [["cve-xxx", {details}], ...]
type VulnerabilityResponse struct {
	Results struct {
		Nvd [][]interface{} `json:"nvd"`
	} `json:"results"`
}

func main() {
	fmt.Printf("Starting threat and vulnerability engine on: %s\n", targetHost)

	// Step 1: Connect to port 22 and grab the raw text banner from the remote server
	banner := grabBanner(targetHost, 22)

	if banner == "" {
		fmt.Println("Could not retrieve banner or port is closed")
		return // Stop execution if the port is closed or connection fails
	}
	fmt.Printf("Raw banner captured: %s\n", banner)

	// Step 2: Extract the software name and version from that banner text
	software, version := parseBanner(banner)

	if software == "" || version == "" {
		fmt.Println("Could not parse software version from banner")
		return
	}

	fmt.Printf("Parsed service target: product = '%s', version = '%s'\n\n", software, version)

	// Step 3: Query the public database using the parsed service details
	fmt.Println("Querying vulnerability intelligence database...")
	lookupVulnerabilities(software, version)
}

// grabBanner opens a TCP connection to the target host and port to grab the raw service banner.
func grabBanner(host string, port int) string {
	address := fmt.Sprintf("%s:%d", host, port) // Forms "scanme.nmap.org:22"

	// Open a TCP connection. If it takes longer than 3 seconds, give up (connection timeout).
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return "" // Connection failed
	}
	defer conn.Close() // "defer" guarantees the connection closes when this function exits

	// If the server doesn't send data within 2 seconds, stop waiting (read timeout)
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Create a reader to read data from the connection
	reader := bufio.NewReader(conn)

	// Read everything until a newline character '\n' is encountered
	banner, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}

	// Clean up any extra spaces or newlines around the banner text
	return strings.TrimSpace(banner)
}

// parseBanner parses the version details specifically looking for OpenSSH format.
func parseBanner(banner string) (string, string) {
	// Look for the starting index of "OpenSSH_" in the banner text
	if idx := strings.Index(banner, "OpenSSH_"); idx != -1 {
		// Slice the banner starting right after "OpenSSH_" -> "6.6.1p1 Ubuntu-2ubuntu2.13"
		versionPart := banner[idx+len("OpenSSH_"):]

		// Split by spaces. fields[0] becomes "6.6.1p1"
		fields := strings.Fields(versionPart)
		if len(fields) > 0 {
			return "openssh", fields[0] // Return software name and version
		}
	}
	return "", ""
}

// extractCvssFromMetrics traverses through the metrics object of a CVE record to find the first valid CVSS score.
func extractCvssFromMetrics(metrics []interface{}) float64 {
	for _, m := range metrics {
		mMap, ok := m.(map[string]interface{})
		if !ok {
			continue
		}
		// Iterate through different CVSS metric standards to find a score
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

// lookupVulnerabilities makes an API request to the CVE lookup service, parses results, and displays relevant CVEs.
func lookupVulnerabilities(product string, version string) {
	// Formulates the API URL: https://cve.circl.lu/api/search/openssh/openssh
	api := fmt.Sprintf("https://cve.circl.lu/api/search/%s/%s", product, product)

	client := http.Client{
		Timeout: 5 * time.Second, // Timeout if the database takes too long to respond
	}

	// Create a GET HTTP request
	req, err := http.NewRequest("GET", api, nil)
	if err != nil {
		fmt.Printf("Error creating API request: %v\n", err)
		return
	}

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("API query failed: %v\n", err)
		return
	}
	defer resp.Body.Close() // Ensure the response body stream is closed afterward

	// Read all downloaded bytes
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading API response: %v\n", err)
		return
	}

	// Unmarshal (parse) the raw JSON bytes into our VulnerabilityResponse struct
	var raw VulnerabilityResponse
	err = json.Unmarshal(body, &raw)
	if err != nil {
		fmt.Printf("Error parsing CVE response: %v\n", err)
		return
	}

	var cveData []CVERecord
	// Loop through every item inside the "nvd" list of the API response
	for _, pair := range raw.Results.Nvd {
		if len(pair) < 2 {
			continue
		}
		// Go interfaces allow any type. We must use Type Assertion (value.(type)) to convert them:
		cveID, ok := pair[0].(string) // Assert that the first element is a string (the CVE ID)
		if !ok {
			continue
		}

		detailMap, ok := pair[1].(map[string]interface{}) // Assert that the second element is a map of details
		if !ok {
			continue
		}

		// Navigate the nested map structure to find the vulnerability description text
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

		// Navigate nested structures to get the CVSS Severity Score (out of 10.0)
		var cvss float64
		if containers, ok := detailMap["containers"].(map[string]interface{}); ok {
			if cna, ok := containers["cna"].(map[string]interface{}); ok {
				if metrics, ok := cna["metrics"].([]interface{}); ok {
					cvss = extractCvssFromMetrics(metrics) // Search CNA metrics
				}
			}
			if cvss == 0 { // If CNA didn't have it, look in the ADP metrics
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

		// Add this cleanly parsed CVE record into our Go list
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

	// Filter to find CVEs whose summary text explicitly mentions our version (e.g. "6.6.1")
	var filteredCVEs []CVERecord
	for _, cve := range cveData {
		if strings.Contains(strings.ToLower(cve.Summary), strings.ToLower(version)) {
			filteredCVEs = append(filteredCVEs, cve)
		}
	}

	// If no CVE summary explicitly mentions our version, show all CVEs for that product
	displayList := filteredCVEs
	if len(displayList) == 0 {
		displayList = cveData
	}

	fmt.Printf("Found %d potential vulnerabilities (showing top match examples):\n\n", len(displayList))

	// Limit display to the top 3 matches
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

		// Truncate the summary to 120 characters so it fits nicely on the screen
		summary := cve.Summary
		if len(summary) > 120 {
			summary = summary[:117] + "..."
		}
		fmt.Printf("Summary: %s\n\n", summary)
	}
}