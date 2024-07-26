package validate

import (
	"github.com/ImAyrix/fallparams/funcs/opt"
	errorutil "github.com/projectdiscovery/utils/errors"
)

func Options(options *opt.Options) error {
	if options.InputUrls == "" && options.InputDIR == "" {
		return errorutil.New("input is empty!")
	}
	if options.MaxLength <= 0 {
		return errorutil.New("maximum length of the parameter (-max-length) must be greater than 0.")
	}
	if options.MaxDepth <= 0 && options.CrawlDuration.Seconds() <= 0 {
		return errorutil.New("either max-depth or crawl-duration must be specified")
	}
	if options.InputDIR != "" && options.InputUrls != "" {
		return errorutil.New("online mode (-url) and offline mode (-directory) cannot be used together")
	}
	if options.InputDIR != "" && options.CrawlMode {
		return errorutil.New("crawl mode (-crawl) and offline mode (-directory) cannot be used together")
	}
	if options.RequestHttpMethod != "" && options.CrawlMode {
		return errorutil.New("crawl mode (-crawl) and custom request method (-method) cannot be used together")
	}
	if options.RequestHttpMethod != "" && options.Headless {
		return errorutil.New("headless mode (-headless) and custom request method (-method) cannot be used together")
	}
	if options.RequestBody != "" && options.CrawlMode {
		return errorutil.New("crawl mode (-crawl) and custom request body (-body) cannot be used together")
	}
	if options.RequestHttpMethod != "" && options.Headless {
		return errorutil.New("headless mode (-headless) and custom request body (-body) cannot be used together")
	}
	if options.MaxLength <= 0 {
		return errorutil.New("the maximum length (-max-length) must be greater than 0.")
	}
	if options.MinLength < 0 {
		return errorutil.New("the minimum length (-min-length) must be greater than 0.")
	}
	if options.MinLength >= options.MaxLength {
		return errorutil.New("The maximum length (-max-length) must be greater than the minimum length (-min-length).")
	}
	return nil
}
