package xss

import (
	"strings"
	// "regexp"
	// "fmt"
)

type OnTagFunc func(sourcePosition int, position int, tag string, html string, isClosing bool) string
type escapeFunc func(html string) string
type onAttrFunc func(name, value string) string

//getTagName get tag name
func getTagName(html string) string {

	if len(html) <= 2 {
		return ""
	}
	var tagName = ""
	i := spaceIndex(html)
	if i == -1 {
		tagName = html[1 : len(html)-1]
	} else {
		tagName = html[1 : i+1]
	}

	tagName = strings.ToLower(strings.TrimSpace(tagName))

	if len(tagName) < 2 {
		return tagName
	}

	if tagName[0:1] == "/" && len(tagName) >= 2 {
		tagName = tagName[1:]
	}

	if tagName[len(tagName)-1:] == "/" {
		tagName = tagName[:len(tagName)-1]
	}

	return tagName
}

//parseTag
func parseTag(html string, onTag OnTagFunc, escapeHtml escapeFunc) string {

	rethtml := ""
	lastPos := 0
	tagStart := -1
	quoteStart := ""
	currentPos := 0
	htmlLen := len(html)
	currentTagName := ""
	currentHtml := ""

chariterator:
	for currentPos = 0; currentPos < htmlLen; currentPos++ {
		c := html[currentPos : currentPos+1]

		if tagStart == -1 {
			if c == "<" {
				tagStart = currentPos
				continue
			}
		} else {
			if quoteStart == "" {

				if c == "<" {
					rethtml += escapeHtml(html[lastPos:currentPos])
					tagStart = currentPos
					lastPos = currentPos
					continue
				}

				if c == ">" {
					rethtml += escapeHtml(html[lastPos:tagStart])
					currentHtml = html[tagStart : currentPos+1]
					currentTagName = getTagName(currentHtml)

					rethtml += onTag(tagStart, len(rethtml), currentTagName, currentHtml, isClosing(currentHtml))

					lastPos = currentPos + 1
					tagStart = -1
					continue

				}

				if c == "'" || c == "\"" {

					i := 1
					ic := html[currentPos-i : currentPos]

					for {

						if !(ic == " " || ic == "=") {
							break
						}

						if ic == "=" {
							quoteStart = c
							continue chariterator
						}
						i = i + 1
						ic = html[currentPos-i : currentPos-i+1]
					}

				}

			} else {
				if c == quoteStart {
					quoteStart = ""
					continue
				}
			}
		}
	}

	if lastPos < len(html) {
		rethtml += escapeHtml(html[lastPos:])
	}

	return rethtml

}

//parseAttr
func parseAttr(html string, onAttr onAttrFunc) string {

	lastPos := 0
	retAttr := []string{}
	tmpName := ""
	htmlLen := len(html)

	addAttr := func(name string, value string) {
		name = strings.TrimSpace(name)
		name = strings.ToLower(regAttr.ReplaceAllString(name, ""))
		if len(name) < 1 {
			return
		}

		ret := onAttr(name, value)
		if len(ret) > 0 {
			retAttr = append(retAttr, ret)
		}

	}

	for i := 0; i < htmlLen; i++ {
		c := html[i : i+1]

		v := ""
		j := -1

		if tmpName == "" && c == "=" {
			tmpName = html[lastPos:i]
			lastPos = i + 1
			continue
		}

		if tmpName != "" {

			if i == lastPos && (c == "\"" || c == "'") && html[i-1:i] == "=" {
				tmpIndex := strings.Index(html[i+1:], c)

				j = i + 1 + tmpIndex
				if tmpIndex == -1 {
					break
				} else {

					v = strings.TrimSpace(html[lastPos+1 : j])
					addAttr(tmpName, v)
					tmpName = ""
					i = j
					lastPos = i + 1
					continue

				}

			}
		}

		//empty
		if regEmtpy.MatchString(c) {

			html = regEmtpy.ReplaceAllString(html, " ")

			if tmpName == "" {
				j = findNextEqual(html, i)

				if j == -1 {
					v = strings.TrimSpace(html[lastPos:i])
					addAttr(v, "")
					tmpName = ""
					lastPos = i + 1
					continue
				} else {
					i = j - 1
					continue
				}
			} else {

				j = findBeforeEqual(html, i-1)

				if j == -1 {
					v = strings.TrimSpace(html[lastPos:i])
					v = stripQuoteWrap(v)
					addAttr(tmpName, v)
					tmpName = ""
					lastPos = i + 1
					continue
				} else {
					continue
				}

			}
		}
	}

	if lastPos < len(html) {

		if tmpName == "" {
			addAttr(html[lastPos:], "")
		} else {
			addAttr(tmpName, stripQuoteWrap(strings.TrimSpace(html[lastPos:])))
		}
	}

	return strings.TrimSpace(strings.Join(retAttr, " "))
}

//isClosing is close tag
func isClosing(html string) bool {
	if len(html) < 2 {
		return false
	}

	return html[0:2] == "</"
}

//isQuoteWrapString
func isQuoteWrapString(text string) bool {

	f := text[0:1]
	e := text[len(text)-1:]
	if (f == "\"" && e == "\"") || (f == "'" && e == "'") {
		return true
	}
	return false
}

//stripQuoteWrap
func stripQuoteWrap(text string) string {
	if isQuoteWrapString(text) {
		return text[1 : len(text)-1]
	}
	return text
}

func findNextEqual(str string, i int) int {

	for ix := i; ix < len(str); ix++ {
		c := str[ix : ix+1]
		if c == " " {
			continue
		}
		if c == "=" {
			return ix
		}
		return -1

	}
	return -1
}

func findBeforeEqual(str string, i int) int {

	for ix := i; ix > 0; ix-- {

		c := str[ix : ix+1]
		if c == " " {
			continue
		}
		if c == "=" {
			return ix
		}
		return -1

	}
	return -1
}
