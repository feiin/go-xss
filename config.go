package xss


type Config struct {

}


//getDefaultWhiteList 默认白名单
func getDefaultWhiteList() map[string][]string {

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

func onTag(tag, html, options string) *string {
	//do nothing 
	return nil
}

