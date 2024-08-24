package active

import (
	"bytes"
	"context"
	"crypto/tls"
	"github.com/ImAyrix/fallparams/funcs/opt"
	"github.com/ImAyrix/fallparams/funcs/utils"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func SendRequest(link string, myOptions *opt.Options) (*http.Response, string) {
	client := &http.Client{
		Timeout: 60 * time.Second,
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	if myOptions.ProxyUrl != "" {
		pUrl, _ := url.Parse(myOptions.ProxyUrl)
		http.DefaultTransport.(*http.Transport).Proxy = http.ProxyURL(pUrl)
	}

	req, err := http.NewRequest(strings.ToUpper(myOptions.RequestHttpMethod), link, bytes.NewBuffer([]byte(myOptions.RequestBody)))
	if err != nil {
		return nil, "temp"
	}
	if myOptions.InputHttpRequest == "" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/114.0")
		req.Header.Set("Referer", link)
	}

	if len(myOptions.CustomHeaders) != 0 {
		for _, v := range myOptions.CustomHeaders {
			req.Header.Set(strings.Split(v, ":")[0], strings.Split(v, ":")[1])
		}
	}
	res, err := client.Do(req)
	var resByte []byte
	if err == nil && res != nil {
		resByte, err = io.ReadAll(res.Body)
		utils.CheckError(err)
	} else {
		return &http.Response{}, "temp"
	}
	if myOptions.Delay != 0 {
		time.Sleep(time.Duration(int32(myOptions.Delay)) * time.Second)
	}
	return res, string(resByte)
}

func HeadlessBrowser(link string, myOptions *opt.Options) string {
	options := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("no-default-browser-check", true),
		chromedp.Flag("disable-infobars", true),
		chromedp.Flag("headless", true),
		chromedp.Flag("enable-automation", false),
		chromedp.Flag("password-store", false),
		chromedp.Flag("disable-extensions", false),
		chromedp.Flag("ignore-certificate-errors", "1"),
	)

	if myOptions.ProxyUrl != "" {
		options = append(options, chromedp.Flag("proxy-server", myOptions.ProxyUrl))
	}

	headers := map[string]interface{}{}
	if myOptions.InputHttpRequest == "" {
		headers = map[string]interface{}{
			"User-Agent":      "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/114.0",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.5",
			"Sec-Fetch-Dest":  "document",
			"Sec-Fetch-Mode":  "navigate",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-User":  "?1",
			"Referer":         link,
		}
	}
	if len(myOptions.CustomHeaders) > 0 {
		for _, head := range myOptions.CustomHeaders {
			key := strings.Split(head, ":")[0]
			value := strings.Split(head, ":")[1][1:]
			headers[key] = value
		}
	}

	// Create a new context
	allocContext, _ := chromedp.NewExecAllocator(context.Background(), options...)
	ctx, cancel := chromedp.NewContext(allocContext)
	defer cancel()

	// Set up network interception to add custom headers
	err := chromedp.Run(ctx, network.Enable(), network.SetExtraHTTPHeaders(headers))
	utils.CheckError(err)

	// Navigate to the URL and retrieve the page DOM
	var htmlContent string
	err = chromedp.Run(ctx,
		chromedp.Navigate(link),
		chromedp.WaitReady("body"),
		chromedp.OuterHTML("html", &htmlContent),
	)
	utils.CheckError(err)

	return htmlContent
}
