package netutil

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
)

func InquireVMPublicIP() (string, error) {
	urls := []string{
		"https://ifconfig.co/",              // xxx.xxx.xxx.xxx
		"https://api.ipify.org?format=text", // xxx.xxx.xxx.xxx
		"http://myexternalip.com/raw",       // xxx.xxx.xxx.xxx
		"https://ident.me/",                 // xxx.xxx.xxx.xxx
	}

	ipChan := make(chan string, 1)
	doneChan := make(chan struct{})
	timeoutChan := time.After(10 * time.Second)

	client := resty.New().
		SetTimeout(3 * time.Second).         // Set the timeout period for each request
		SetRetryCount(3).                    // Set the number of retries
		SetRetryWaitTime(1 * time.Second).   // Set the wait time between retries
		SetRetryMaxWaitTime(3 * time.Second) // Set the maximum wait time between retries

	// Try to get the public IP address from each URL
	for _, url := range urls {
		go func(url string) {
			select {
			case <-doneChan: // break all goroutines if a public IP address is obtained from another goroutine.
				return
			default:
				resp, err := client.R().Get(url)
				// break the goroutine if an error occurs while sending a request.
				if err != nil {
					return
				}
				// break the goroutine if the response status code is not 200.
				if resp.StatusCode() != 200 {
					return
				}

				trimmed := strings.TrimSuffix(string(resp.Body()), "\n")
				if net.ParseIP(trimmed) != nil {
					select {
					case ipChan <- trimmed:
						// fmt.Printf("Public IP address acquire from %s: %s\n", url, trimmed)
					case <-doneChan:
					}
				}
			}
		}(url)
	}

	select {
	case hostPublicIP := <-ipChan: // obtain the public IP address from the channel
		close(doneChan)          // close the done channel to break all goroutines
		return hostPublicIP, nil // return the public IP address
	case <-timeoutChan: // break all goroutines if the timeout period is exceeded.
		return "", fmt.Errorf("Failed to acquire public IP address within the timeout period")
	}
}
