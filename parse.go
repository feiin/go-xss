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


//isClosing is close tag
func isClosing(html string) bool{
	if len(html) < 2 {
		return false
	}
	
	return html[0:2] == "</"
}