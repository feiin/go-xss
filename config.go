package xss


import (
	"strconv"
	"strings"
	// "fmt"
)
type Config struct {

	//remove invisible characters
	StripBlankChar bool

	// remove html comments
	AllowCommentTag bool

	// StripIgnoreTagBody
	StripIgnoreTagBody []string

	WhiteList map[string][]string


}

type TagOption struct {
	SourcePosition int
	Position int
	IsClosing bool
	IsWhite bool

}



type OnIgnoreTagFunc func(tag string,html string, options TagOption) *string

type StripTagBodyResult struct {
	OnIgnoreTag OnIgnoreTagFunc
	Remove  func(html string) string
}
//GetDefaultWhiteList 默认白名单
func GetDefaultWhiteList() map[string][]string {

	result :=  map[string][]string {
	"a": {"target", "href", "title"},
    "abbr": {"title"},
    "address": {},
    "area": {"shape", "coords", "href", "alt"},
    "article": {},
    "aside": {},
    "audio": {"autoplay", "controls", "loop", "preload", "src"},
    "b": {},
    "bdi": {"dir"},
    "bdo": {"dir"},
    "big": {},
    "blockquote": {"cite"},
    "br": {},
    "caption": {},
    "center": {},
    "cite": {},
    "code": {},
    "col": {"align", "valign", "span", "width"},
    "colgroup": {"align", "valign", "span", "width"},
    "dd": {},
    "del": {"datetime"},
    "details": {"open"},
    "div": {},
    "dl": {},
    "dt": {},
    "em": {},
    "font": {"color", "size", "face"},
    "footer": {},
    "h1": {},
    "h2": {},
    "h3": {},
    "h4": {},
    "h5": {},
    "h6": {},
    "header": {},
    "hr": {},
    "i": {},
    "img": {"src", "alt", "title", "width", "height"},
    "ins": {"datetime"},
    "li": {},
    "mark": {},
    "nav": {},
    "ol": {},
    "p": {},
    "pre": {},
    "s": {},
    "section": {},
    "small": {},
    "span": {},
    "sub": {},
    "sup": {},
    "strong": {},
    "table": {"width", "border", "align", "valign"},
    "tbody": {"align", "valign"},
    "td": {"width", "rowspan", "colspan", "align", "valign"},
    "tfoot": {"align", "valign"},
    "th": {"width", "rowspan", "colspan", "align", "valign"},
    "thead": {"align", "valign"},
    "tr": {"rowspan", "align", "valign"},
    "tt": {},
    "u": {},
    "ul": {},
    "video": {"autoplay", "controls", "loop", "preload", "src", "height", "width"},
	}

	return result
}

func OnTag(tag, html string, options TagOption) *string {
	//do nothing 
	return nil
}

func OnTagAttr(tag, name, value string) *string {
	//do nothing 
	return nil
}


func OnIgnoreTag(tag, html string, options TagOption) *string {
	return nil
}

func OnIgnoreTagAttr(tag,name, value string,isWhiteAttr bool) *string {
	return nil
}

func ScapeHtml(html string) string {
	return regGT.ReplaceAllString(regLT.ReplaceAllString(html,"&lt;"),"&gt;")
}

func StripTagBody(tags []string,next OnIgnoreTagFunc) StripTagBodyResult{
	
	isRemoveAllTag := len(tags) == 0

	var isRemoveTag = func (tag string) bool {
		if isRemoveAllTag {
			return true
		}

		for _, item := range tags {
			if item ==  tag {
				return true
			}
		}
		return false
	}

	var removeList [][]int
	posStart := -1

	
	result := StripTagBodyResult{}

	result.OnIgnoreTag = func(tag string,html string, options TagOption) *string {
		if isRemoveTag(tag) {
			if options.IsClosing {
				var ret = "[/removed]"
				var end = options.Position + len(ret)
				  
				if posStart == -1 {
					removeList = append(removeList,[]int{options.Position, end})
				} else {
					removeList = append(removeList,[]int{posStart,end})
				}

				posStart = -1
				return &ret
			} 

			if posStart != -1 {
				posStart = options.Position
			}
			ret := "[removed]"
			return &ret

		}
		return next(tag,html, options)

	}

	result.Remove = func(html string) string {
		var rethtml = ""
		var lastPos = 0
		for _,item := range removeList {
			rethtml += html[lastPos:item[0]]
			lastPos = item[1]
		}
   
      	rethtml += html[lastPos:];
      	return rethtml;
	}

	return result
	
}


func isSafeLinkValue(value string) bool {

	vl :=len(value)
	if vl == 0 {
		return true
	}

	if value[0] == '#' || value[0] == '/' {
		return true
	}

	if vl >= 2 && value[0:2] == "./" {
		return true
	}

	if vl >= 3 && value[0:3] == "../" {
		return true
	}

	if vl >= 4 && value[0:4] == "tel:" {
		return true
	}

	if vl >= 6 && value[0:6] == "ftp:" {
		return true
	}


	if vl >= 7 && (value[0:7] == "http://" || value[0:7] == "mailto:")  {
		return true
	}

	if vl >= 9 && (value[0:8] == "https://")  {
		return true
	}

	if vl >= 11 && (value[0:11] == "data:image/")  {
		return true
	}

	return false
}

func SafeAttrValue(tag, name, value string) string {

	value = friendlyAttrValue(value)
	if name == "href" || name == "src" { 

		value = strings.TrimSpace(value)
		if value == "#" {
			return "#"
		}

 
		if !isSafeLinkValue(value) {
			return ""
		}

	} else if  name == "background" && regDefaultOnTagAttr4.MatchString(value) {
		return ""
	} else if name == "style" {

		if regDefaultOnTagAttr7.MatchString(value) {
			return ""
		}

		if regDefaultOnTagAttr8.MatchString(value) {
			if regDefaultOnTagAttr4.MatchString(value) {
				return ""
			}
		}


	}

	value = EscapeAttrValue(value)
	return value
}

//friendlyAttrValue get friendly attribute value
func friendlyAttrValue(str string) string {
 	str = UnescapeQuote(str)
	str = EscapeHtmlEntities(str)
	str = EscapeDangerHtml5Entities(str)
	str = ClearNonPrintableCharacter(str)
	return str
}


//UnescapeQuote unescape double quote 
func UnescapeQuote(str string) string {
	return regQuote2.ReplaceAllString(str,"\"")
}

//EscapeHtmlEntities
func EscapeHtmlEntities(str string) string {
	return regAttrValue1.ReplaceAllStringFunc(str, func(input string) string {
		input = input[2:]

		if input[len(input)-1] == ';' {
			input = input[:len(input)-1]
		}

		if input[0] == 'x' || input[0] == 'X' {
			i,err := strconv.ParseInt(input[1:],16,32)
			if err == nil {

				return string(i)
			}
			return ""
			
		}
		i,err := strconv.Atoi(input)
		if err == nil {
			return string(i)
		}

		return ""
	})
}

//EscapeDangerHtml5Entities
func EscapeDangerHtml5Entities(str string) string {
   return regAttrNewLine.ReplaceAllString(regAttrValueColon.ReplaceAllString(str,":")," ")
}

//ClearNonPrintableCharacter
func ClearNonPrintableCharacter(str string) string {
	chs := []rune(str)
 
	result := []rune{}

	for _, item := range chs {

		if item < 32 {
			result= append(result,rune(' '))
		} else {
			result= append(result,item)
		}

	}

	return strings.TrimSpace(string(result))
}


func EscapeQuote(str string) string {
	return regQuote.ReplaceAllString(str,"&quot;")
}

func EscapeHtml(html string) string {
	return regGT.ReplaceAllString(regLT.ReplaceAllString(html,"&lt;"),"&gt;")
}


func EscapeAttrValue(str string) string {
	str = EscapeQuote(str)
	str = EscapeHtml(str)

	return str
}