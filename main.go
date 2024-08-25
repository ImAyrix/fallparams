package main

import (
	"github.com/ImAyrix/fallparams/funcs/opt"
	"github.com/ImAyrix/fallparams/funcs/run"
	"github.com/ImAyrix/fallparams/funcs/utils"
	"github.com/ImAyrix/fallparams/funcs/validate"
	"github.com/projectdiscovery/goflags"
	"os"
	"sync"
)

var (
	wg        sync.WaitGroup
	myOptions = &opt.Options{}
)

const (
	VERSION = "1.0.12"
)

func ReadFlags() *goflags.FlagSet {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("Find All Parameters")

	createGroup(flagSet, "input", "Input",
		flagSet.StringVarP(&myOptions.InputUrls, "url", "u", "", "Input [Filename | URL]"),
		flagSet.StringVarP(&myOptions.InputDIR, "directory", "dir", "", "Stored requests/responses files directory path (offline)"),
		flagSet.StringVarP(&myOptions.InputHttpRequest, "request", "r", "", "File containing the raw http request"),
	)

	createGroup(flagSet, "rate-limit", "Rate-Limit",
		flagSet.IntVarP(&myOptions.Thread, "thread", "t", 1, "Number of Threads [Number]"),
		flagSet.IntVarP(&myOptions.Delay, "delay", "rd", 0, "Request delay between each request in seconds"),
	)

	createGroup(flagSet, "configs", "Configurations",
		flagSet.BoolVarP(&myOptions.CrawlMode, "crawl", "c", false, "Crawl pages to extract their parameters"),
		flagSet.IntVarP(&myOptions.MaxDepth, "depth", "d", 2, "maximum depth to crawl"),
		flagSet.DurationVarP(&myOptions.CrawlDuration, "crawl-duration", "ct", 0, "maximum duration to crawl the target"),
		flagSet.BoolVarP(&myOptions.Headless, "headless", "hl", false, "Discover parameters with headless browser"),
		flagSet.VarP(&myOptions.CustomHeaders, "header", "H", "Header `\"Name: Value\"`, separated by colon. Multiple -H flags are accepted."),
		flagSet.StringVarP(&myOptions.RequestHttpMethod, "method", "X", "GET", "HTTP method to use"),
		flagSet.StringVarP(&myOptions.RequestBody, "body", "b", "", "POST data"),
		flagSet.StringVarP(&myOptions.ProxyUrl, "proxy", "x", "", "Proxy URL (SOCKS5 or HTTP). For example: http://127.0.0.1:8080 or socks5://127.0.0.1:8080"),
	)

	createGroup(flagSet, "output", "Output",
		flagSet.StringVarP(&myOptions.OutputFile, "output", "o", "parameters.txt", "File to write output to"),
		flagSet.IntVarP(&myOptions.MaxLength, "max-length", "xl", 30, "Maximum length of words"),
		flagSet.IntVarP(&myOptions.MinLength, "min-length", "nl", 0, "Minimum length of words"),
		flagSet.BoolVar(&myOptions.SilentMode, "silent", false, "Disables the banner and prints output to the command line."),
	)

	createGroup(flagSet, "update", "Update",
		flagSet.BoolVarP(&myOptions.DisableUpdateCheck, "disable-update-check", "duc", false, "Disable automatic fallparams update check"),
	)
	err := flagSet.Parse()
	utils.CheckError(err)

	return flagSet
}

func main() {
	_ = ReadFlags()
	if myOptions.InputHttpRequest != "" {
		utils.ParseHttpRequest(myOptions)
	}
	err := validate.Options(myOptions)
	utils.CheckError(err)

	var channel = utils.GetInput(myOptions)
	utils.ShowBanner(VERSION, len(channel), myOptions)
	_, _ = os.Create(myOptions.OutputFile)

	for i := 0; i < myOptions.Thread; i++ {
		wg.Add(1)
		go run.Start(channel, myOptions, &wg)
	}
	wg.Wait()

	defer utils.FinalMessage(myOptions)
}

func createGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
	flagSet.SetGroup(groupName, description)
	for _, currentFlag := range flags {
		currentFlag.Group(groupName)
	}
}
