package xss

import (
	// "errors"
	// "bytes"
	"strings"
	"github.com/feiin/pkg/arrays"
	// "fmt"
	// "io"
)


type Xss struct {
	options *XssOption
}

//NewXss 
func NewXss(options XssOption) *Xss {
	xss := &Xss{
		options: &options,
		
	}
	defaultOption := NewDefaultXssOption()

	if options.OnTag == nil {
		options.OnTag = defaultOption.OnTag
	}

	if options.OnTagAttr == nil {
		options.OnTagAttr = defaultOption.OnTagAttr
	}

	if options.OnIgnoreTag == nil {
		options.OnIgnoreTag = defaultOption.OnIgnoreTag
	}

	if options.OnIgnoreTagAttr == nil {
		options.OnIgnoreTagAttr = defaultOption.OnIgnoreTagAttr
	}

	if options.EscapeHTML == nil {
		options.EscapeHTML = defaultOption.EscapeHTML
	}

	if options.SafeAttrValue == nil {
		options.SafeAttrValue = defaultOption.SafeAttrValue
	}

	if options.UnescapeQuote == nil {
		options.UnescapeQuote = defaultOption.UnescapeQuote
	}

	if options.EscapeQuote == nil {
		options.EscapeQuote = defaultOption.EscapeQuote
	}

	if options.EscapeAttrValue == nil {
		options.EscapeAttrValue = defaultOption.EscapeAttrValue
	}

	if options.WhiteList == nil {
		options.WhiteList = defaultOption.WhiteList
	}

	return xss

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
	html = strings.TrimSpace(html[i+1:len(html)-1])

	isClosing := html[len(html)-1] == '/'

	if isClosing {
		html = strings.TrimSpace(html[0:len(html)-1])
	}
	return AttrResult {
		Html:html,
		Closing:isClosing,
	}

} 

//Process 处理xss
func (x *Xss) Process(html string) (string) {

	if len(html) < 3 {
		return html
	}
 
	onIgnoreTag := x.options.OnIgnoreTag
	escapeHTML := x.options.EscapeHTML
	onTag := x.options.OnTag
	onTagAttr := x.options.OnTagAttr
	safeAttrValue := x.options.SafeAttrValue
	OnIgnoreTagAttr := x.options.OnIgnoreTagAttr
	whiteList := x.options.WhiteList

  	//remove invisible characters
  	if x.options.StripBlankChar {
		html = stripBlankChar(html)
	}

	// remove html comments
	if !x.options.AllowCommentTag {
		html = stripCommentTag(html)
	}

	// if enable stripIgnoreTagBody
	var stripIgnoreTagBody StripTagBodyResult
	if x.options.StripIgnoreTagBody != nil {
		stripIgnoreTagBody = x.options.StripTagBody( x.options.StripIgnoreTagBody, onIgnoreTag)
		onIgnoreTag = stripIgnoreTagBody.OnIgnoreTag
	}

	retHTML := parseTag(html,func(sourcePosition int,position int,tag string,html string, isClosing bool) string {
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

			attrsHTML := parseAttr(attrs.Html, func(name,value string) string{
				isWhiteAttr := arrays.ContainsString(whiteAttrList, name) != -1

				ret := onTagAttr(tag, name, value)

				if ret != nil {
					return *ret
				}

				if isWhiteAttr {
					value = safeAttrValue(tag,name, value)
					if len(value) > 0 {
						return name + "=\""+value+"\""
					} else {
						return name
					}
				} else {
					ret := OnIgnoreTagAttr(tag,name,value, isWhiteAttr)
					if ret != nil {
						return *ret
					}
					return ""
					
				}
 			})

			html := "<"+tag
			if len(attrsHTML) > 0 {
				html += " "+attrsHTML
			}

			if attrs.Closing {
				html += " /"
			}

			html += ">"
			return html
		} else {
			ret := onIgnoreTag(tag,html ,info)
			if ret != nil {
				return *ret
			}
			return escapeHTML(html);
		}

	}, escapeHTML)


	if x.options.StripIgnoreTagBody != nil {
		retHTML = stripIgnoreTagBody.Remove(retHTML)
	}

	return retHTML
}

