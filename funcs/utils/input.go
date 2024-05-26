package utils

import (
	"github.com/ImAyrix/fallparams/funcs/opt"
	"github.com/ImAyrix/fallparams/funcs/validate"
	"github.com/projectdiscovery/gologger"
	"os"
	"path/filepath"
	"strings"
)

func GetInput(options *opt.Options) chan string {
	var allUrls []string
	if options.InputUrls != "" {
		allUrls = Read(options.InputUrls)
		allUrls = Unique(validate.Clear(allUrls))
	} else if options.InputDIR != "" {
		allUrls = DIR(options.InputDIR)
	}

	channel := make(chan string, len(allUrls))
	for _, myLink := range allUrls {
		channel <- myLink
	}
	close(channel)

	return channel
}

func Read(input string) []string {
	if validate.IsUrl(input) {
		return []string{input}
	}
	fileByte, err := os.ReadFile(input)
	CheckError(err)
	return strings.Split(string(fileByte), "\n")
}

func DIR(directory string) []string {
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
	CheckError(err)

	return result
}
