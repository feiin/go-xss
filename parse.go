package xss

import (
	"strings"
)

//getTagName get tag name
func getTagName(html string) string {

	var tagName = ""
	i := spaceIndex(html)
	if i == -1 {
		tagName = html[1:len(html)-1]
	} else {
		tagName =  html[1:i+1]
	}

	tagName = strings.ToLower(strings.TrimSpace(tagName))

	if tagName[0:1] == "/" {
		tagName = tagName[1:]
	}

	if tagName[len(tagName)-1:] == "/" {
		tagName = tagName[:len(tagName)-1]
	}

	return tagName
}	