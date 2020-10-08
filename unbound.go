package letsdebug

import (
	"bufio"
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	rootKeyContents = `.       172800  IN      DNSKEY  257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
	.       172800  IN      DNSKEY  256 3 8 AwEAAdp440E6Mz7c+Vl4sPd0lTv2Qnc85dTW64j0RDD7sS/zwxWDJ3QRES2VKDO0OXLMqVJSs2YCCSDKuZXpDPuf++YfAu0j7lzYYdWTGwyNZhEaXtMQJIKYB96pW6cRkiG2Dn8S2vvo/PxW9PKQsyLbtd8PcwWglHgReBVp7kEv/Dd+3b3YMukt4jnWgDUddAySg558Zld+c9eGWkgWoOiuhg4rQRkFstMX1pRyOSHcZuH38o1WcsT4y3eT0U/SR6TOSLIB/8Ftirux/h297oS7tCcwSPt0wwry5OFNTlfMo8v7WGurogfk8hPipf7TTKHIi20LWen5RCsvYsQBkYGpF78=
	.       172800  IN      DNSKEY  257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=
	.       172800  IN      RRSIG   DNSKEY 8 0 172800 20181101000000 20181011000000 20326 . M/LTswhCjuJUTvX1CFqC+TiJ4Fez7AROa5mM+1AI2MJ+zLHhr3JaMxyydFLWrBHR0056Hz7hNqQ9i63hGeiR6uMfanF0jIRb9XqgGP8nY37T8ESpS1UiM9rJn4b40RFqDSEvuFdd4hGwK3EX0snOCLdUT8JezxtreXI0RilmqDC2g44TAKyFw+Is9Qwl+k6+fbMQ/atA8adANbYgyuHfiwQCCUtXRaTCpRgQtsAz9izO0VYIGeHIoJta0demAIrLCOHNVH2ogHTqMEQ18VqUNzTd0aGURACBdS7PeP2KogPD7N8Q970O84TFmO4ahPIvqO+milCn5OQTbbgsjHqY6Q==`

	unboundConfContents = `server:
    edns-buffer-size: 512
    directory: "."
    auto-trust-anchor-file: "%s"
    pidfile: ""
    logfile: ""
    chroot: ""
    username: ""
    log-replies: yes
    log-queries: yes
    num-threads: 1
    so-reuseport: yes
    verbosity: 2
    use-syslog: no
    log-time-ascii: yes
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes
    tcp-upstream: no
    port: %d
    private-address: 192.168.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-address: 169.254.0.0/16
    private-address: fd00::/8
    private-address: fe80::/10
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: yes
    cache-min-ttl: 0
    cache-max-ttl: 0
    cache-max-negative-ttl: 0
    neg-cache-size: 0
    prefetch: no
    unwanted-reply-threshold: 10000
    do-not-query-localhost: yes
    val-clean-additional: yes
    val-sig-skew-max: 0
    val-sig-skew-min: 0
    ipsecmod-enabled: no`

	portMin = 20000
	portMax = 25000
)

var (
	portChan   chan int
	configPath string
)

func init() {
	portChan = make(chan int)
	go func() {
		for {
			for i := portMin; i <= portMax; i++ {
				portChan <- i
			}
		}
	}()

	var err error
	configPath, err = os.UserConfigDir()
	if err != nil {
		configPath, err = os.UserCacheDir()
		if err != nil {
			configPath = os.TempDir()
		}
	}
	if configPath == "" {
		log.Fatal("unable to find directory for unbound files")
	}

	configPath = filepath.Join(configPath, "letsdebug")

	_ = os.Mkdir(configPath, 0755)

	rootKeyFile := filepath.Join(configPath, "root.key")
	if !fileExists(rootKeyFile) {
		debug("Writing unbound root.key ta to: %s\n", rootKeyFile)
		if err := ioutil.WriteFile(rootKeyFile, []byte(rootKeyContents), 0644); err != nil {
			log.Fatalf("error writing root key file %q: %v", rootKeyFile, err)
		}
	}

	printedConfOutput := false
	for i := portMin; i <= portMax; i++ {
		unboundConfFile := filepath.Join(configPath, fmt.Sprintf("unbound%d.conf", i))
		if !fileExists(unboundConfFile) {
			if !printedConfOutput {
				printedConfOutput = true
				debug("Writing unbound config to: %s\n", unboundConfFile)
			}
			if err := ioutil.WriteFile(unboundConfFile, []byte(fmt.Sprintf(unboundConfContents, rootKeyFile, i)), 0644); err != nil {
				log.Fatalf("error writing conf file %q: %v", unboundConfFile, err)
			}
		}
	}
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func lookup(name string, rrType uint16) ([]dns.RR, error) {
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	port := <-portChan
	unboundConfFile := filepath.Join(configPath, fmt.Sprintf("unbound%d.conf", port))

	path := os.Getenv("LETSDEBUG_UNBOUND_PATH")
	if path == "" {
		path = "unbound"
	} else {
		path = filepath.Join(path, "unbound")
	}

	// TODO: pass through a parent context for this?
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer func() {
		cancel()
	}()

	cmd := exec.CommandContext(ctx, path, "-p", "-d", "-c", unboundConfFile)
	errPipe, _ := cmd.StderrPipe()

	// start the unbound process
	debug("[unbound-%d] Starting unbound: %s\n", port, strings.Join(cmd.Args, " "))
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("error starting unbound: %w", err)
	}
	defer func() {
		debug("[unbound-%d] unbound closing\n", port)
		cmd.Process.Kill()
		cmd.Wait()
		debug("[unbound-%d] unbound closed\n", port)
	}()

	// listen for the start of service output
	readyChan := make(chan bool)
	go func() {
		scanner := bufio.NewScanner(errPipe)
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "start of service") {
				readyChan <- true
			}
			debug("[unbound-%d] output: %s\n", port, scanner.Text())
		}
	}()

	// wait for unbound
	select {
	case <-time.After(1 * time.Second):
		break
	case <-readyChan:
		break
	}

	// spin off a go func to exchange a dns request
	type dnsResult struct {
		r   *dns.Msg
		err error
	}
	dnsChan := make(chan dnsResult)
	go func() {
		c := new(dns.Client)
		c.Timeout = time.Second * 30
		m := new(dns.Msg)
		m.SetQuestion(name, rrType)
		r, _, err := c.Exchange(m, fmt.Sprintf("127.0.0.1:%d", port))
		dnsChan <- dnsResult{r, err}
	}()

	// wait for either the dns response or the timeout context to finish
	select {
	case result := <-dnsChan:
		if result.err != nil {
			return nil, result.err
		}

		if result.r.Rcode == dns.RcodeServerFailure || result.r.Rcode == dns.RcodeRefused {
			return nil, fmt.Errorf("DNS response for %s/%s did not have an acceptable response code: %s",
				name, dns.TypeToString[rrType], dns.RcodeToString[result.r.Rcode])
		}

		return result.r.Answer, nil

	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
