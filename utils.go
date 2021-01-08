package xss


import (
	"regexp"
	// "fmt"
)

var reg = regexp.MustCompile("\\s|\\n|\\t")
var regComment = regexp.MustCompile("<!--[\\s\\S]*?-->")
var regLT = regexp.MustCompile("<")
var regGT = regexp.MustCompile(">")
var regQuote = regexp.MustCompile("\"")
var regQuote2 = regexp.MustCompile("&quot;")
var regAttrValue1 = regexp.MustCompile("(?im)&#([a-zA-Z0-9]*);?")
var regAttrValueColon = regexp.MustCompile("(?im)&colon;?");
var regAttrNewLine = regexp.MustCompile("(?im)&newline;?")
var regDefaultOnTagAttr4 = regexp.MustCompile("(?i)((j\\s*a\\s*v\\s*a|v\\s*b|l\\s*i\\s*v\\s*e)\\s*s\\s*c\\s*r\\s*i\\s*p\\s*t\\s*|m\\s*o\\s*c\\s*h\\s*a)\\:")
var regDefaultOnTagAttr5 = regexp.MustCompile("(?i)^[\\s\"'`]*(d\\s*a\\s*t\\s*a\\s*)\\:")
var regDefaultOnTagAttr6 = regexp.MustCompile("(?i)^[\\s\"'`]*(d\\s*a\\s*t\\s*a\\s*)\\:\\s*image\\/")
var regDefaultOnTagAttr7 = regexp.MustCompile("(?i)e\\s*x\\s*p\\s*r\\s*e\\s*s\\s*s\\s*i\\s*o\\s*n\\s*\\(.*")
var regDefaultOnTagAttr8 = regexp.MustCompile("(?i)u\\s*r\\s*l\\s*\\(.*");

//spaceIndex get the pos of first space
func spaceIndex(str string) int {
	locs := reg.FindStringIndex(str)

	if locs != nil {
		return locs[0]
	}

	return -1
}

//remove html comments
func stripCommentTag(html string) string {
	return regComment.ReplaceAllString(html,"")
}

//remove invisible characters
func stripBlankChar(html string) string {

	chs := []rune(html)
 
	n := len(chs)


	items := []rune{}
	for i := 0; i < n; i++ {
		ch := chs[i]
		if ch == 127 {
			continue
		}

		if ch <= 13 {
			if ch == 10 || ch == 13 {
				items = append(items,ch)
			}
			continue
		}

		items = append(items,ch)

	}

	return string(items)
	
}