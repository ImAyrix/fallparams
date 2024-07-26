package opt

import (
	"github.com/projectdiscovery/goflags"
	_ "strings"
	"time"
)

type Options struct {
	InputUrls          string
	InputDIR           string
	Thread             int
	Delay              int
	CrawlMode          bool
	MaxDepth           int
	CrawlDuration      time.Duration
	Headless           bool
	CustomHeaders      goflags.StringSlice
	OutputFile         string
	MaxLength          int
	MinLength          int
	DisableUpdateCheck bool
	RequestHttpMethod  string
	RequestBody        string
}
