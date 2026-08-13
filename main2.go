package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const targetHost = "scanme.nmap.org"

func main() {
	fmt.Printf("Starting Advanced Security Probe on: %s\n\n", targetHost)

	var wg sync.WaitGroup
	portsToProbe := []int{22, 80}

	for _, port := range portsToProbe {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			probeServiceBanner(targetHost, p)
		}(port)

	}
	wg.Wait()

}

func probeServiceBanner(host string, port int) {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	fmt.Printf("Open port detected: port %d/TCP\n", port)
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if port == 80 {
		fmt.Fprintf(conn, "GET/ HTTP/ 1.1\r\nHost: %s\r\n\r\n", host)
	}
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		fmt.Print("Connected but server remained silent")
		return
	}
	cleanBanner := strings.TrimSpace(banner)
	fmt.Printf("Service banner identified: %s\n\n", cleanBanner)
}
