package main

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// Target host to scan
const targetHost = "scanme.nmap.org"

func main() {
	fmt.Printf("Starting Security Scan on: %s\n", targetHost)
	fmt.Println("Scanning ports 1 to 100...\n")

	start := time.Now()

	var wg sync.WaitGroup

	for port := 1; port <= 100; port++ {
		wg.Add(1)

		go func(p int) {
			defer wg.Done()
			scanPort(targetHost, p)
		}(port)
	}

	// Wait for all port probes to finish
	wg.Wait()

	fmt.Printf("\n Scan complete in %v!\n", time.Since(start))
}

func scanPort(host string, port int) {
	address := fmt.Sprintf("%s:%d", host, port)

	// Try to complete a TCP handshake with a 1.5-second timeout
	conn, err := net.DialTimeout("tcp", address, 1500*time.Millisecond)
	if err != nil {
		// Port is closed or filtered
		return
	}

	// If connection succeeded, the port is OPEN
	conn.Close()
	fmt.Printf("[+] OPEN PORT DETECTED: Port %d/TCP\n", port)
}
