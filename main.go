package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type arrayFlags []string

var (
	customHeaders                          arrayFlags
	sleepTime, thread, maxLength, maxDepth int
	headlessP, headlessC, crawlMode        bool
	inputUrls, outputFile, filesDIR        string
	wg                                     sync.WaitGroup
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	VERSION     = "1.0.7"
)

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func (i *arrayFlags) String() string {
	return "my string representation"
}

func main() {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("Find All Parameters")

	createGroup(flagSet, "input", "Input",
		flagSet.StringVarP(&inputUrls, "url", "u", "", "Input [Filename | URL]"),
		flagSet.StringVarP(&filesDIR, "files", "f", "", "Stored requests/responses files directory path (offline)"),
	)

	createGroup(flagSet, "rate-limit", "Rate-Limit",
		flagSet.IntVarP(&thread, "thread", "t", 1, "Number Of Thread [Number]"),
		flagSet.IntVarP(&sleepTime, "sleep", "s", 0, "Time for sleep after sending each request"),
	)

	createGroup(flagSet, "configs", "Configurations",
		flagSet.BoolVarP(&crawlMode, "crawl", "c", false, "Crawl pages to extract their parameters"),
		flagSet.IntVarP(&maxDepth, "depth", "d", 2, "maximum depth to crawl"),
		flagSet.BoolVarP(&headlessC, "headless-crawl", "hc", false, "Enable headless hybrid crawling (experimental)"),
		flagSet.BoolVarP(&headlessP, "headless-parameter", "hp", false, "Discover parameters with headless browser"),
		flagSet.VarP(&customHeaders, "header", "H", "Header `\"Name: Value\"`, separated by colon. Multiple -H flags are accepted."),
	)

	createGroup(flagSet, "output", "Output",
		flagSet.StringVarP(&outputFile, "output", "o", "parameters.txt", "File to write output to"),
		flagSet.IntVarP(&maxLength, "max-length", "l", 30, "Maximum length of words"),
	)
	_ = flagSet.Parse()
	checkUpdate()

	if inputUrls == "" && filesDIR == "" {
		gologger.Error().Msg("Input is empty!\n")
		gologger.Info().Msg("Use -h flag for help.\n\n")
		os.Exit(1)
	}

	var userInput []string
	if inputUrls != "" {
		allUrls := readInput(inputUrls)
		if crawlMode {
			for _, v := range allUrls {
				allUrls = append(allUrls, simpleCrawl(v, sleepTime, headlessC, maxDepth)...)
			}
		}

		allUrls = clearUrls(allUrls)
		allUrls = unique(allUrls)
		userInput = allUrls
	} else if filesDIR != "" {
		userInput = readDir(filesDIR)
	}
	_, _ = os.Create(outputFile)

	channel := make(chan string, len(userInput))
	for _, myLink := range userInput {
		channel <- myLink
	}
	close(channel)

	for i := 0; i < thread; i++ {
		wg.Add(1)
		go saveResult(channel)
	}
	wg.Wait()

	defer finalMessage()
}

func readInput(input string) []string {
	if IsUrl(input) {
		return []string{input}
	}
	fileByte, err := os.ReadFile(input)
	checkError(err)
	return strings.Split(string(fileByte), "\n")
}

func IsUrl(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func simpleCrawl(link string, delay int, headlessMode bool, maxDepth int) []string {
	var allLinks []string
	options := &types.Options{
		MaxDepth:               maxDepth, // Maximum depth to crawl
		ScrapeJSResponses:      true,
		ScrapeJSLuiceResponses: false,
		CrawlDuration:          0,
		Timeout:                10,
		Headless:               headlessMode,
		UseInstalledChrome:     false,
		ShowBrowser:            false,
		HeadlessNoSandbox:      true,
		HeadlessNoIncognito:    false,
		Scope:                  nil,
		OutOfScope:             nil,
		Delay:                  delay,
		NoScope:                false,
		DisplayOutScope:        false,
		OutputMatchRegex:       nil,
		OutputFilterRegex:      nil,
		KnownFiles:             "all",
		ExtensionsMatch:        nil,
		ExtensionFilter:        nil,
		Silent:                 true,
		OutputMatchCondition:   "NOTANYMATCHCONDITION",
		FieldScope:             "rdn",           // Crawling Scope Field
		BodyReadSize:           2 * 1024 * 1024, // Maximum response size to read
		RateLimit:              150,             // Maximum requests to send per second
		Strategy:               "depth-first",   // Visit strategy (depth-first, breadth-first)
		OnResult: func(result output.Result) { // Callback function to execute for result
			allLinks = append(allLinks, result.Request.URL)
		},
	}
	crawlerOptions, err := types.NewCrawlerOptions(options)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
	defer crawlerOptions.Close()
	crawler, err := standard.New(crawlerOptions)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
	defer crawler.Close()
	err = crawler.Crawl(link)
	if err != nil {
		gologger.Warning().Msgf("Could not crawl %s: %s", link, err.Error())
	}
	defer gologger.Info().Msg(fmt.Sprintf("%d endpoints were found by crawling\n\n", len(allLinks)-1))
	return allLinks
}

func sendRequest(link string) (*http.Response, string) {
	client := &http.Client{
		Timeout: 60 * time.Second,
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	req, err := http.NewRequest("GET", link, nil)
	if err != nil {
		return nil, "temp"
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Referer", link)

	if len(customHeaders) != 0 {
		for _, v := range customHeaders {
			req.Header.Set(strings.Split(v, ":")[0], strings.Split(v, ":")[1])
		}
	}
	res, err := client.Do(req)
	var resByte []byte
	if err == nil && res != nil {
		resByte, err = io.ReadAll(res.Body)
		checkError(err)
	} else {
		return &http.Response{}, "temp"
	}
	if sleepTime != 0 {
		time.Sleep(time.Duration(int32(sleepTime)) * time.Second)
	}
	return res, string(resByte)
}

func headlessBrowser(link string) string {
	options := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("no-default-browser-check", true),
		chromedp.Flag("disable-infobars", true),
		chromedp.Flag("headless", true),
		chromedp.Flag("enable-automation", false),
		chromedp.Flag("password-store", false),
		chromedp.Flag("disable-extensions", false),
	)

	headers := map[string]interface{}{
		"User-Agent":      "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/114.0",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.5",
		"Sec-Fetch-Dest":  "document",
		"Sec-Fetch-Mode":  "navigate",
		"Sec-Fetch-Site":  "none",
		"Sec-Fetch-User":  "?1",
		"Referer":         link,
	}
	if len(customHeaders) > 0 {
		for _, head := range customHeaders {
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
	checkError(err)

	// Navigate to the URL and retrieve the page DOM
	var htmlContent string
	_ = chromedp.Run(ctx,
		chromedp.Navigate(link),
		chromedp.WaitReady("body"),
		chromedp.OuterHTML("html", &htmlContent),
	)

	return htmlContent
}

func myRegex(myRegex string, response string, indexes []int) []string {
	r, e := regexp.Compile(myRegex)
	checkError(e)
	allName := r.FindAllStringSubmatch(response, -1)
	var finalResult []string
	for _, index := range indexes {
		for _, v := range allName {
			if v[index] != "" {
				finalResult = append(finalResult, v[index])
			}
		}
	}
	return finalResult
}

func startDiscovery(myInput string) []string {
	var result []string
	if IsUrl(myInput) {
		gologger.Info().Msg("Started parameter discovery for => " + myInput + "\n")
		body := ""
		httpRes := &http.Response{}
		if !headlessP {
			httpRes, body = sendRequest(myInput)
		} else {
			body = headlessBrowser(myInput)
		}
		cnHeader := strings.ToLower(httpRes.Header.Get("Content-Type"))

		result = findParameters(myInput, body, cnHeader)
	} else if len(myInput) != 0 {
		cnHeader := "NOT-FOUND"
		link := ""
		fileName := strings.Split(myInput, "{==MY=FILE=NAME==}")[0]
		myInput = strings.Split(myInput, "{==MY=FILE=NAME==}")[1]
		reg, _ := regexp.Compile(`[cC][oO][nN][tT][eE][nN][tT]-[tT][yY][pP][eE]\s*:\s*([\w\-/]+)`)

		if IsUrl(strings.Split(myInput, "\n")[0]) {
			link = strings.Split(myInput, "\n")[0]
		} else {
			link = fileName
		}

		if len(reg.FindStringSubmatch(myInput)) != 0 {
			cnHeader = strings.ToLower(reg.FindStringSubmatch(myInput)[1])
		}
		gologger.Info().Msg("Started parameter discovery for => " + link + "\n")
		result = findParameters(link, myInput, cnHeader)

	}
	defer gologger.Info().Msg(fmt.Sprintf("%d parameters were found\n\n", len(result)))
	return result
}

func findParameters(link string, body string, cnHeader string) []string {
	var allParameter []string
	var result []string
	// Get parameter from url
	linkParameter := queryStringKey(link)
	allParameter = append(allParameter, linkParameter...)

	// Variable Name
	variableNamesRegex := myRegex(`(let|const|var)\s([\w\,\s]+)\s*?(\n|\r|;|=)`, body, []int{2})
	var variableNames []string
	for _, v := range variableNamesRegex {
		for _, j := range strings.Split(v, ",") {
			variableNames = append(variableNames, strings.Replace(j, " ", "", -1))
		}
	}
	allParameter = append(allParameter, variableNames...)

	// Json and Object keys
	jsonObjectKey := myRegex(`["|']([\w\-]+)["|']\s*?:`, body, []int{1})
	allParameter = append(allParameter, jsonObjectKey...)

	// String format variable
	stringFormat := myRegex(`\${(\s*[\w\-]+)\s*}`, body, []int{1})
	allParameter = append(allParameter, stringFormat...)

	// Function input
	funcInput := myRegex(`.*\(\s*["|']?([\w\-]+)["|']?\s*(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?\)`,
		body, []int{1, 3, 5, 7, 9, 11, 13, 15, 17, 19})
	allParameter = append(allParameter, funcInput...)

	// Path Input
	pathInput := myRegex(`\/\{(.*)\}`, body, []int{1})
	allParameter = append(allParameter, pathInput...)

	// Query string key in source
	queryString := myRegex(`(\?([\w\-]+)=)|(\&([\w\-]+)=)`, body, []int{2, 4})
	allParameter = append(allParameter, queryString...)

	if cnHeader != "application/javascript" {
		// Name HTML attribute
		inputName := myRegex(`name\s*?=\s*?["|']([\w\-]+)["|']`, body, []int{1})
		allParameter = append(allParameter, inputName...)

		// ID HTML attribute
		htmlID := myRegex(`id\s*=\s*["|']([\w\-]+)["|']`, body, []int{1})
		allParameter = append(allParameter, htmlID...)
	}

	// XML attributes
	if strings.Contains(cnHeader, "xml") {
		xmlAtr := myRegex(`<([a-zA-Z0-9$_\.-]*?)>`, body, []int{1})
		allParameter = append(allParameter, xmlAtr...)
	}
	for _, v := range allParameter {
		if v != "" {
			result = append(result, v)
		}
	}
	return result
}

func queryStringKey(link string) []string {
	u, e := url.Parse(link)
	checkError(e)
	var keys []string
	for _, v := range strings.Split(u.RawQuery, "&") {
		keys = append(keys, strings.Split(v, "=")[0])
	}
	return keys
}

func unique(strSlice []string) []string {
	keys := make(map[string]bool)
	var list []string
	for _, entry := range strSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			if entry != "" {
				list = append(list, entry)
			}
		}
	}
	return list
}

func saveResult(channel chan string) {
	defer wg.Done()
	for v := range channel {
		for _, i := range unique(startDiscovery(v)) {
			if len(i) <= maxLength {
				file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_WRONLY, 0666)
				checkError(err)
				_, err = fmt.Fprintln(file, i)
				checkError(err)
				err = file.Close()
				checkError(err)
			}
		}
	}
}

func createGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
	flagSet.SetGroup(groupName, description)
	for _, currentFlag := range flags {
		currentFlag.Group(groupName)
	}
}

func checkUpdate() {
	// Check Updates
	resp, err := http.Get("https://github.com/ImAyrix/fallparams")
	checkError(err)

	respByte, err := io.ReadAll(resp.Body)
	checkError(err)
	body := string(respByte)

	re, e := regexp.Compile(`fallparams\s+v(\d\.\d\.\d+)`)
	checkError(e)

	if re.FindStringSubmatch(body)[1] != VERSION {
		gologger.Print().Msg("")
		gologger.Print().Msg("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -")
		gologger.Print().Msg(fmt.Sprintf("|    %v🔥  Please update Fallparams!%v                                      |", colorGreen, colorReset))
		gologger.Print().Msg("|    💣  Run: go install github.com/ImAyrix/fallparams@latest           |")
		gologger.Print().Msg("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -")
		gologger.Print().Msg("")
	}

}

func clearUrls(links []string) []string {
	badExtensions := []string{
		".css", ".jpg", ".jpeg", ".png", ".svg", ".img", ".gif", ".exe", ".mp4", ".flv", ".pdf", ".doc", ".ogv", ".webm", ".wmv",
		".webp", ".mov", ".mp3", ".m4a", ".m4p", ".ppt", ".pptx", ".scss", ".tif", ".tiff", ".ttf", ".otf", ".woff", ".woff2", ".bmp",
		".ico", ".eot", ".htc", ".swf", ".rtf", ".image", ".rf"}
	var result []string

	for _, link := range links {
		isGoodUrl := true
		u, _ := url.Parse(link)

		for _, ext := range badExtensions {
			if strings.HasSuffix(strings.ToLower(u.Path), ext) {
				isGoodUrl = false
			}
		}

		if isGoodUrl {
			result = append(result, link)
		}
	}
	return result
}

func readDir(directory string) []string {
	if _, err := os.Stat(directory); os.IsNotExist(err) {
		gologger.Fatal().Msg("Not Exist")
	}

	var result []string
	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			dat, _ := os.ReadFile(path)
			result = append(result, info.Name()+"{==MY=FILE=NAME==}"+string(dat))
		}
		return err
	})
	checkError(err)

	return result
}

func finalMessage() {
	dat, _ := os.ReadFile(outputFile)
	uniqData := strings.Join(unique(strings.Split(string(dat), "\n")), "\n")
	_ = os.WriteFile(outputFile, []byte(uniqData), 0644)

	if len(string(dat)) != 0 {
		gologger.Info().Msg(fmt.Sprintf("Parameter wordlist %ssuccessfully%s generated and saved to %s%s%s [%d unique parameters]",
			colorGreen, colorReset, colorBlue, outputFile, colorReset, len(strings.Split(uniqData, "\n"))))
	} else {
		_ = os.Remove(outputFile)
		gologger.Error().Msg("I'm sorry, but I couldn't find any parameters :(")
	}
}

func checkError(e error) {
	if e != nil {
		fmt.Println(e.Error())
		gologger.Fatal().Msg("x")
	}
}
