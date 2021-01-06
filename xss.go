package xss

import (
	// "errors"
	// "bytes"
	"strings"
	"github.com/feiin/pkg/arrays"
	// "io"
)


type Xss struct {
	options *Config
}

//NewXss 
func NewXss() *Xss {
	return &Xss{}
}

type AttrResult struct {
	Html string
	Closing bool
}

func GetAttrs(html string) AttrResult {
	i := spaceIndex(html)
	if i == -1 {
		return AttrResult { 
			Html:"",
			Closing: html[len(html)-2] == '/',
		}
	}
	html = strings.TrimSpace(html[i+1:])

	isClosing := html[len(html)-1] == '/'

	if isClosing {
		html = strings.TrimSpace(html[0:len(html)-1])
	}
	return AttrResult {
		Html:html,
		Closing:isClosing
	}

} 

//Process 处理xss
func (x *Xss) Process(html string) (string) {

	whiteList := GetDefaultWhiteList()
	if len(html) < 3 {
		return html
	}

	onIgnoreTag := OnIgnoreTag
	scapeHtml := ScapeHtml
	onTag := OnTag
	onTagAttr := OnTagAttr
  	//remove invisible characters
  	if x.options.StripBlankChar {
		html = stripBlankChar(html)
	}

	// remove html comments
	if x.options.AllowCommentTag {
		html = stripCommentTag(html)
	}

	// if enable stripIgnoreTagBody
	if x.options.StripIgnoreTagBody != nil {
		var stripIgnoreTagBody = StripTagBody( x.options.StripIgnoreTagBody, onIgnoreTag)
		onIgnoreTag = stripIgnoreTagBody.OnIgnoreTag
	}

	retHtml := parseTag(html,func(sourcePosition int,position int,tag string,html string, isClosing bool) string {
		isWhite := false

		if _, ok := whiteList[tag]; ok {
			isWhite = true
		}
		info := TagOption {
			SourcePosition: sourcePosition,
			Position: position,
			IsClosing: isClosing,
			IsWhite: isWhite,
		}

		ret := onTag(tag, html,info)

		if ret != nil {
			return *ret
		}

		if info.IsWhite {
			if info.IsClosing {
				return "</" + tag + ">";
			}

			attrs := GetAttrs(html)

			var whiteAttrList []string

			if whiteList, ok := whiteList[tag];ok {
				whiteAttrList = whiteList
			}

			attrsHtml := parseAttr(attrs.Html, func(name,value string) string{
				isWhiteAttr = arrays.ContainsString(whiteAttrList, name) != -1

				ret := onTagAttr(tag, name, value)

				if ret != nil {
					return *ret
				}

				if isWhiteAttr {
					
				}
			})


		}

		return ""

	}, scapeHtml)







	return ""
}

