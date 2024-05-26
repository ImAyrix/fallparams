package active

import (
	"github.com/ImAyrix/fallparams/funcs/opt"
	"github.com/ImAyrix/fallparams/funcs/parameters"
	"github.com/ImAyrix/fallparams/funcs/utils"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
	"math"
)

func SimpleCrawl(link string, myOptions *opt.Options) []string {
	var allParams []string
	options := &types.Options{
		MaxDepth:               myOptions.MaxDepth, // Maximum depth to crawl
		ScrapeJSResponses:      true,
		ScrapeJSLuiceResponses: true,
		CrawlDuration:          myOptions.CrawlDuration,
		Timeout:                10,
		Retries:                1,
		Headless:               myOptions.Headless,
		UseInstalledChrome:     false,
		ShowBrowser:            false,
		HeadlessNoSandbox:      true,
		HeadlessNoIncognito:    false,
		TlsImpersonate:         false,
		CustomHeaders:          myOptions.CustomHeaders,
		IgnoreQueryParams:      false,
		Scope:                  nil,
		OutOfScope:             nil,
		Delay:                  myOptions.Delay,
		NoScope:                false,
		DisplayOutScope:        false,
		OutputMatchRegex:       nil,
		OutputFilterRegex:      nil,
		KnownFiles:             "all",
		ExtensionsMatch:        nil,
		ExtensionFilter: []string{
			".css", ".jpg", ".jpeg", ".png", ".svg", ".img", ".gif", ".exe", ".mp4", ".flv", ".pdf", ".doc", ".ogv", ".webm", ".wmv",
			".webp", ".mov", ".mp3", ".m4a", ".m4p", ".ppt", ".pptx", ".scss", ".tif", ".tiff", ".ttf", ".otf", ".woff", ".woff2", ".bmp",
			".ico", ".eot", ".htc", ".swf", ".rtf", ".image", ".rf"},
		Silent:           true,
		FieldScope:       "rdn", // Crawling Scope Field
		BodyReadSize:     math.MaxInt,
		DisableRedirects: false,
		RateLimit:        150,           // Maximum requests to send per second
		Strategy:         "depth-first", // Visit strategy (depth-first, breadth-first)
		OnResult: func(result output.Result) {
			if result.HasResponse() {
				allParams = append(allParams, parameters.Find(
					result.Request.URL,
					result.Response.Body,
					result.Response.Resp.Header.Get("Content-Type"))...,
				)
			}
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
	utils.Silent()
	err = crawler.Crawl(link)
	if err != nil {
		gologger.Warning().Msgf("Could not crawl %s: %s", link, err.Error())
	}
	defer utils.Speak()

	return allParams
}
