package utils

import (
	"encoding/base64"
	"fmt"
	"github.com/ImAyrix/fallparams/funcs/opt"
	"github.com/projectdiscovery/gologger"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
)

const (
	colorReset = "\033[0m"
	colorGreen = "\033[32m"
	colorBlue  = "\033[34m"
	colorRed   = "\033[0;31m"
)

var (
	OriginalStdout *os.File = os.Stdout
	OriginalStderr *os.File = os.Stderr
)

func Unique(strSlice []string) []string {
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

func ShowBanner(version string, inputLength int, myOptions *opt.Options) {
	var banner = "ICAgIF9fX19fXyAgICAgIF9fX18gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgIC8gX19fXy9fX18gXy8gLyAvX19fICBfX19fIF9fX19fX19fX18gX19fX18gX19fICBfX19fXwogIC8gL18gIC8gX18gYC8gLyAvIF9fIFwvIF9fIGAvIF9fXy8gX18gYC8gX18gYF9fIFwvIF9fXy8KIC8gX18vIC8gL18vIC8gLyAvIC9fLyAvIC9fLyAvIC8gIC8gL18vIC8gLyAvIC8gLyAoX18gICkgCi9fLyAgICBcX18sXy9fL18vIC5fX18vXF9fLF8vXy8gICBcX18sXy9fLyAvXy8gL18vX19fXy8gIAogICAgICAgICAgICAgICAvXy8gICAgIGJ5IEBJbUF5cml4ICAgICAgICAgICAgVjEuMC4wICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA=="
	bannerByte, _ := base64.StdEncoding.DecodeString(banner)
	gologger.Print().Msgf("%s\n\n", strings.Replace(string(bannerByte), "1.0.0", version, 1))

	// Check Updates
	if !myOptions.DisableUpdateCheck {
		resp, err := http.Get("https://github.com/ImAyrix/fallparams")
		CheckError(err)
		respByte, err := io.ReadAll(resp.Body)
		CheckError(err)
		body := string(respByte)
		re, e := regexp.Compile(`fallparams\s+v(\d\.\d\.\d+)`)
		CheckError(e)

		msg := ""
		if msg = fmt.Sprintf("an %soutdated%s", colorRed, colorReset); re.FindStringSubmatch(body)[1] == version {
			msg = fmt.Sprintf("the %slatest%s", colorGreen, colorReset)
		}
		gologger.Info().Msgf("Installed fallparams is the %s version", msg)
	}
	gologger.Info().Msgf("Started creating a custom parameter wordlist using %d URLs", inputLength)
	if myOptions.CrawlMode {
		gologger.Info().Msgf("Crawl mode has been enabled\n")
	}
}

func FinalMessage(options *opt.Options) {
	dat, _ := os.ReadFile(options.OutputFile)
	uniqData := strings.Join(Unique(strings.Split(string(dat), "\n")), "\n")
	_ = os.WriteFile(options.OutputFile, []byte(uniqData), 0644)

	if len(string(dat)) != 0 {
		gologger.Info().Msg(fmt.Sprintf("Parameter wordlist %ssuccessfully%s generated and saved to %s%s%s [%d unique parameters]",
			colorGreen, colorReset, colorBlue, options.OutputFile, colorReset, len(strings.Split(uniqData, "\n"))))
	} else {
		_ = os.Remove(options.OutputFile)
		gologger.Error().Msg("I'm sorry, but I couldn't find any parameters :(")
	}
}

func CheckError(e error) {
	if e != nil {
		gologger.Fatal().Msg(e.Error())
	}
}

func Silent() {
	devNull, err := os.Open(os.DevNull)
	CheckError(err)
	os.Stdout = devNull
	os.Stderr = devNull
}

func Speak() {
	os.Stdout = OriginalStdout
	os.Stderr = OriginalStderr
}

func MyRegex(myRegex string, response string, indexes []int) []string {
	r, e := regexp.Compile(myRegex)
	CheckError(e)
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
