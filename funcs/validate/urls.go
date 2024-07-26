package validate

import (
	"net/url"
	"strings"
)

func Clear(links []string) []string {
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

		if !IsUrl(link) {
			isGoodUrl = false
		}

		if isGoodUrl {
			result = append(result, link)
		}
	}
	return result
}

func IsUrl(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}
