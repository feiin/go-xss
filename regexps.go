package xss

import (
	"regexp"
)

var regAttr = regexp.MustCompile("[^a-zA-Z0-9_:\\.\\-]")
var regEmtpy = regexp.MustCompile("\\s|\\n|\\t")
var regSpace = regexp.MustCompile("\\s|\\n|\\t")
var regComment = regexp.MustCompile("<!--[\\s\\S]*?-->")
var regLT = regexp.MustCompile("<")
var regGT = regexp.MustCompile(">")
var regQuote = regexp.MustCompile("\"")
var regQuote2 = regexp.MustCompile("&quot;")
var regAttrValue1 = regexp.MustCompile("(?im)&#([a-zA-Z0-9]*);?")
var regAttrValueColon = regexp.MustCompile("(?im)&colon;?")
var regAttrNewLine = regexp.MustCompile("(?im)&newline;?")
var regDefaultOnTagAttr4 = regexp.MustCompile("(?i)((j\\s*a\\s*v\\s*a|v\\s*b|l\\s*i\\s*v\\s*e)\\s*s\\s*c\\s*r\\s*i\\s*p\\s*t\\s*|m\\s*o\\s*c\\s*h\\s*a)\\:")
var regDefaultOnTagAttr5 = regexp.MustCompile("(?i)^[\\s\"'`]*(d\\s*a\\s*t\\s*a\\s*)\\:")
var regDefaultOnTagAttr6 = regexp.MustCompile("(?i)^[\\s\"'`]*(d\\s*a\\s*t\\s*a\\s*)\\:\\s*image\\/")
var regDefaultOnTagAttr7 = regexp.MustCompile("(?i)e\\s*x\\s*p\\s*r\\s*e\\s*s\\s*s\\s*i\\s*o\\s*n\\s*\\(.*")
var regDefaultOnTagAttr8 = regexp.MustCompile("(?i)u\\s*r\\s*l\\s*\\(.*")
