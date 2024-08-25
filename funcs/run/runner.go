package run

import (
	"fmt"
	"github.com/ImAyrix/fallparams/funcs/active"
	"github.com/ImAyrix/fallparams/funcs/opt"
	"github.com/ImAyrix/fallparams/funcs/parameters"
	"github.com/ImAyrix/fallparams/funcs/utils"
	"github.com/ImAyrix/fallparams/funcs/validate"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
)

func Do(inp string, myOptions *opt.Options) []string {
	var params []string
	if validate.IsUrl(inp) {
		if myOptions.CrawlMode {
			params = append(params, active.SimpleCrawl(inp, myOptions)...)
		} else {
			body := ""
			httpRes := &http.Response{}
			if !myOptions.Headless {
				httpRes, body = active.SendRequest(inp, myOptions)
			} else {
				body = active.HeadlessBrowser(inp, myOptions)
			}
			cnHeader := strings.ToLower(httpRes.Header.Get("Content-Type"))

			params = append(params, parameters.Find(inp, body, cnHeader)...)
		}
	} else if len(inp) != 0 {
		cnHeader := "NOT-FOUND"
		link := ""
		fileName := strings.Split(inp, "{==MY=FILE=NAME==}")[0]
		body := strings.Split(inp, "{==MY=FILE=NAME==}")[1]
		reg, _ := regexp.Compile(`[cC][oO][nN][tT][eE][nN][tT]-[tT][yY][pP][eE]\s*:\s*([\w\-/]+)`)

		if validate.IsUrl(strings.Split(inp, "\n")[0]) {
			link = strings.Split(inp, "\n")[0]
		} else {
			link = fileName
		}

		if len(reg.FindStringSubmatch(inp)) != 0 {
			cnHeader = strings.ToLower(reg.FindStringSubmatch(inp)[1])
		}
		params = append(params, parameters.Find(link, body, cnHeader)...)
	}
	return params
}

func Start(channel chan string, myOptions *opt.Options, wg *sync.WaitGroup) {
	defer wg.Done()
	for v := range channel {
		for _, i := range utils.Unique(Do(v, myOptions)) {
			if len(i) <= myOptions.MaxLength && len(i) >= myOptions.MinLength {
				if myOptions.SilentMode {
					fmt.Println(i)
				}
				if myOptions.OutputFile != "parameters.txt" || !myOptions.SilentMode {
					file, err := os.OpenFile(myOptions.OutputFile, os.O_APPEND|os.O_WRONLY, 0666)
					utils.CheckError(err)
					_, err = fmt.Fprintln(file, i)
					utils.CheckError(err)
					err = file.Close()
					utils.CheckError(err)
				}
			}
		}
	}
}
