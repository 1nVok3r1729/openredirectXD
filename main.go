package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

//var proxyURL, _ = url.Parse("http://127.0.0.1:8080")

var transport = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: time.Second,
		DualStack: true,
	}).DialContext,
	//Proxy: http.ProxyURL(proxyURL),
}

var httpClient = &http.Client{
	Transport: transport,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func main() {
	var payload string
	flag.StringVar(&payload, "p", "none", "Specify payload to use")

	var threads int
	flag.IntVar(&threads, "t", 20, "Specify number of threads to run")
	flag.Parse()

	if payload != "none" {
		if !isValidUrl(payload) {
			fmt.Println("Invalid payload: Example: https://google.com")
			return
		}
	}

	var wg sync.WaitGroup
	urls := make(chan string)

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go workers(urls, &wg, payload)
	}

	input := bufio.NewScanner(os.Stdin)
	for input.Scan() {
		parsed, _ := url.Parse(input.Text())
		if len(parsed.Query()) == 0 {
			continue
		}
		urls <- input.Text()
	}
	close(urls)
	wg.Wait()
}

func checkredirect(s, payload string) {
	if payload != "none" {
		parsed, _ := url.Parse(payload)
		resp, err := httpClient.Get(changeparams(s, payload))
		if err != nil {
			return
		}
		if resp.StatusCode == 302 || resp.StatusCode == 301 || resp.StatusCode == 304 {
			if strings.Contains(resp.Header.Get("Location"), parsed.Host) {
				fmt.Println(s, "is vulnerable to open redirect")
			}
		}
	} else {
		resp, err := httpClient.Get(changeparams(s, "http://evil.com"))
		if err != nil {
			return
		}
		if resp.StatusCode == 302 || resp.StatusCode == 301 || resp.StatusCode == 304 {
			if strings.Contains(resp.Header.Get("Location"), "evil.com") {
				fmt.Println(s, "is vulnerable to open redirect")
			}
		}
	}
}

func changeparams(s, value string) string {
	parsed, _ := url.Parse(s)
	values := url.Values{}
	for a := range parsed.Query() {
		values.Add(a, value)
	}
	return parsed.Scheme + "://" + parsed.Host + parsed.Path + "?" + values.Encode()
}

func workers(cha chan string, wg *sync.WaitGroup, payload string) {
	for i := range cha {
		checkredirect(i, payload)
	}
	wg.Done()
}

func isValidUrl(toTest string) bool {
	_, err := url.ParseRequestURI(toTest)
	if err != nil {
		return false
	}

	u, err := url.Parse(toTest)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}

	return true
}
