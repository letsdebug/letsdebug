package letsdebug

import (
	"context"
	"net"
	"net/http"
	"time"
)

const (
	httpTimeout = 10
)

func checkHTTP(domain string, address net.IP) error {
	dialer := net.Dialer{
		Timeout: httpTimeout * time.Second,
	}
	transport := http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if address.To16() != nil {
				return dialer.DialContext(ctx, "tcp", "["+address.String()+"]:80")
			}
			return dialer.DialContext(ctx, "tcp", address.String()+":80")
		},
	}

	req, err := http.NewRequest("GET", "http://"+domain+"/.well-known/acme-challenge/letsdebug-test", nil)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout*time.Second)
	defer cancel()

	req = req.WithContext(ctx)

	cl := http.Client{
		Transport: &transport,
	}

	resp, err := cl.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	return nil
}
