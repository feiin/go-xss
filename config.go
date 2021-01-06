package xss


type Config struct {

	//remove invisible characters
	StripBlankChar bool

	// remove html comments
	AllowCommentTag bool

	// StripIgnoreTagBody
	StripIgnoreTagBody []string


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

				posStart = -1;
				return ret;
			} 

			if posStart != -1 {
				posStart = options.Position
			}
			return "[removed]"

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


func SafeAttrValue(tag, name, value string) string {

}