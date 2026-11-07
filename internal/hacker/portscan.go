package hacker

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

type PortScanAction struct{}

func (a *PortScanAction) Metadata() ActionMetadata {
	return ActionMetadata{
		Name:        "Port Scanner",
		Description: "TCP connect scan of top 100 ports on discovered hosts",
		Priority:    35,
		Requires:    []string{"has_subdomain"},
		Provides:    []string{"has_ports"},
	}
}

var topPorts = []int{
	21, 22, 23, 25, 53, 80, 81, 110, 111, 135,
	139, 143, 389, 443, 445, 465, 514, 587, 593, 636,
	993, 995, 1025, 1026, 1027, 1028, 1029, 1080, 1194, 1352,
	1433, 1434, 1521, 1723, 2049, 2082, 2083, 2181, 2375, 2376,
	3000, 3128, 3306, 3389, 3690, 4000, 4040, 4443, 4444, 4848,
	5000, 5001, 5432, 5555, 5632, 5800, 5900, 5901, 5984, 6000,
	6001, 6082, 6379, 6443, 6666, 6667, 6668, 6669, 7000, 7001,
	7002, 7077, 8000, 8001, 8008, 8009, 8080, 8081, 8082, 8083,
	8084, 8085, 8086, 8087, 8088, 8089, 8090, 8181, 8443, 8888,
	9000, 9001, 9042, 9090, 9092, 9100, 9200, 9300, 9418, 9999,
}

func (a *PortScanAction) Execute(ctx context.Context, target string, kb *Knowledge, client *transport.Client) ActionResult {
	hosts := extractHosts(kb, target)
	if len(hosts) == 0 {
		return ActionResult{}
	}

	maxHosts := 3
	if len(hosts) > maxHosts {
		hosts = hosts[:maxHosts]
	}

	maxPorts := 30
	ports := topPorts
	if len(ports) > maxPorts {
		ports = ports[:maxPorts]
	}

	// Vet every host once, through the same boundary an HTTP request takes:
	// a host outside the scope, or one that resolves to an internal address
	// under --block-internal, is refused before a single SYN. A refusal is
	// reported, not silently turned into a clean-looking scan.
	type vettedHost struct {
		host string
		ips  []net.IP
	}
	var vetted []vettedHost
	var refused []Finding
	for _, host := range hosts {
		if client == nil {
			refused = append(refused, refusedProbeFinding(host, "no scoped transport client"))
			continue
		}
		ips, err := client.ProbeHost(ctx, host)
		if err != nil {
			refused = append(refused, refusedProbeFinding(host, types.Sanitize(err.Error())))
			continue
		}
		vetted = append(vetted, vettedHost{host: host, ips: ips})
	}
	if len(vetted) == 0 {
		return ActionResult{Findings: refused}
	}

	type scanTarget struct {
		host string
		addr string
		port int
	}

	targets := make(chan scanTarget)
	results := make(chan Finding, 100)

	var wg sync.WaitGroup
	var seenOpen sync.Map
	numWorkers := 20

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range targets {
				select {
				case <-ctx.Done():
					return
				default:
				}

				conn, err := net.DialTimeout("tcp", t.addr, 2*time.Second)
				if err != nil {
					continue
				}
				// Probe port only: the close error of a dial-done
				// probe connection carries no operator signal.
				_ = conn.Close()

				key := fmt.Sprintf("%s|%d", t.host, t.port)
				if _, loaded := seenOpen.LoadOrStore(key, struct{}{}); loaded {
					continue
				}

				service := guessService(t.port)
				results <- Finding{
					Type:        "open_port",
					Name:        fmt.Sprintf("Open port: %s/%d (%s)", t.host, t.port, service),
					Severity:    classifyPortSeverity(t.port),
					Description: fmt.Sprintf("Port %d open on %s — %s", t.port, t.host, service),
					Evidence:    t.addr,
				}

				kb.AddEndpoint(Endpoint{
					Path:        t.addr,
					Method:      "TCP",
					Status:      0,
					ContentType: service,
				})
			}
		}()
	}

	go func() {
		for _, vh := range vetted {
			for _, ip := range vh.ips {
				for _, port := range ports {
					select {
					case <-ctx.Done():
						close(targets)
						return
					default:
						targets <- scanTarget{
							host: vh.host,
							addr: net.JoinHostPort(ip.String(), strconv.Itoa(port)),
							port: port,
						}
					}
				}
			}
		}
		close(targets)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var findings []Finding
	for f := range results {
		findings = append(findings, f)
	}
	findings = append(findings, refused...)

	return ActionResult{Findings: findings}
}

// refusedProbeFinding records a host the boundary would not let the scanner
// touch, so a report never reads "nothing open" when the truth is "nothing
// was probed".
func refusedProbeFinding(host, reason string) Finding {
	return Finding{
		Type:        "probe_refused",
		Name:        "Port scan refused: " + host,
		Severity:    SevInfo,
		Description: "The scope boundary refused this host — its ports were NOT tested",
		Evidence:    reason,
	}
}

func extractHosts(kb *Knowledge, target string) []string {
	var hosts []string
	seen := make(map[string]bool)

	caps := kb.GetCapabilities()
	for _, c := range caps {
		if c.Name == "has_subdomain" && c.Details != nil {
			if list, ok := c.Details["list"]; ok {
				for _, h := range strings.Split(list, ", ") {
					h = strings.TrimSpace(h)
					if h != "" && !seen[h] {
						hosts = append(hosts, h)
						seen[h] = true
					}
				}
			}
		}
	}

	targetHost := extractDomain(target)
	if !seen[targetHost] {
		hosts = append(hosts, targetHost)
	}

	return hosts
}

func guessService(port int) string {
	services := map[int]string{
		21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
		80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS",
		143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
		514: "Syslog", 587: "SMTP", 593: "HTTP RPC", 636: "LDAPS",
		993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
		1352: "Lotus Notes", 1433: "MSSQL", 1434: "MSSQL Browser",
		1521: "Oracle DB", 1723: "PPTP", 2049: "NFS", 2181: "ZooKeeper",
		2375: "Docker", 2376: "Docker TLS", 3000: "HTTP-Alt",
		3128: "Squid", 3306: "MySQL", 3389: "RDP", 3690: "SVN",
		4000: "HTTP-Alt", 4443: "HTTPS-Alt", 4848: "GlassFish",
		5000: "HTTP-Alt", 5432: "PostgreSQL", 5555: "Android ADB",
		5632: "PCAnywhere", 5800: "VNC-Alt", 5900: "VNC",
		5984: "CouchDB", 6379: "Redis", 6443: "HTTPS-Alt",
		6667: "IRC", 7001: "WebLogic", 7077: "Mesos",
		8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
		8888: "HTTP-Alt", 9000: "HTTP-Alt", 9042: "Cassandra",
		9090: "HTTP-Alt", 9092: "Kafka", 9200: "Elasticsearch",
		9300: "Elasticsearch", 9418: "Git", 9999: "HTTP-Alt",
	}
	if s, ok := services[port]; ok {
		return s
	}
	return "Unknown"
}

func classifyPortSeverity(port int) Severity {
	switch port {
	case 21, 23, 25, 110, 143, 135, 445, 2049, 3389, 3306, 5432, 6379, 27017:
		return SevHigh
	case 22:
		return SevLow
	case 80, 443:
		// The port we reached the web target through. An open 80/443 on an
		// HTTP site is the expected transport, not a finding — rating it
		// MEDIUM made every scan carry two lines of pure noise.
		return SevInfo
	case 53, 389, 636, 993, 995:
		return SevLow
	default:
		return SevLow
	}
}
