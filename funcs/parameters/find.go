package parameters

import (
	"github.com/ImAyrix/fallparams/funcs/utils"
	"net/url"
	"strings"
)

func QueryStringKey(link string) []string {
	u, e := url.Parse(link)
	utils.CheckError(e)
	var keys []string
	for _, v := range strings.Split(u.RawQuery, "&") {
		keys = append(keys, strings.Split(v, "=")[0])
	}
	return keys
}

func Find(link string, body string, cnHeader string) []string {
	var allParameter []string
	var result []string
	// Get parameter from url
	linkParameter := QueryStringKey(link)
	allParameter = append(allParameter, linkParameter...)

	// Variable Name
	variableNamesRegex := utils.MyRegex(`(let|const|var)\s([\w\,\s]+)\s*?(\n|\r|;|=)`, body, []int{2})
	var variableNames []string
	for _, v := range variableNamesRegex {
		for _, j := range strings.Split(v, ",") {
			variableNames = append(variableNames, strings.Replace(j, " ", "", -1))
		}
	}
	allParameter = append(allParameter, variableNames...)

	// Json and Object keys
	jsonObjectKey := utils.MyRegex(`["|']([\w\-]+)["|']\s*?:`, body, []int{1})
	allParameter = append(allParameter, jsonObjectKey...)

	// String format variable
	stringFormat := utils.MyRegex(`\${(\s*[\w\-]+)\s*}`, body, []int{1})
	allParameter = append(allParameter, stringFormat...)

	// Function input
	funcInput := utils.MyRegex(`.*\(\s*["|']?([\w\-]+)["|']?\s*(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?\)`,
		body, []int{1, 3, 5, 7, 9, 11, 13, 15, 17, 19})
	allParameter = append(allParameter, funcInput...)

	// Path Input
	pathInput := utils.MyRegex(`\/\{(.*)\}`, body, []int{1})
	allParameter = append(allParameter, pathInput...)

	// Query string key in source
	queryString := utils.MyRegex(`(\?([\w\-]+)=)|(\&([\w\-]+)=)`, body, []int{2, 4})
	allParameter = append(allParameter, queryString...)

	if cnHeader != "application/javascript" {
		// Name HTML attribute
		inputName := utils.MyRegex(`name\s*?=\s*?["|']([\w\-]+)["|']`, body, []int{1})
		allParameter = append(allParameter, inputName...)

		// ID HTML attribute
		htmlID := utils.MyRegex(`id\s*=\s*["|']([\w\-]+)["|']`, body, []int{1})
		allParameter = append(allParameter, htmlID...)
	}

	// XML attributes
	if strings.Contains(cnHeader, "xml") {
		xmlAtr := utils.MyRegex(`<([a-zA-Z0-9$_\.-]*?)>`, body, []int{1})
		allParameter = append(allParameter, xmlAtr...)
	}
	for _, v := range allParameter {
		if v != "" {
			result = append(result, v)
		}
	}
	return result
}
