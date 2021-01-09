package xss

import (
	"testing"
 
)


func TestGetTagName(t *testing.T) {
	x:="<a href=\"https://example.com\">"

	tagName := getTagName(x)

	if tagName != "a" {
		t.Errorf("get tagname1 err %s",tagName)
	}

	t.Logf("get tag name1 %s", tagName)

	x="<br/>"

	tagName = getTagName(x)

	if tagName != "br" {
		t.Errorf("get tagname2 err %s",tagName)
	}

	t.Logf("get tag name2 %s", tagName)

	x="</strong>"

	tagName = getTagName(x)

	if tagName != "strong" {
		t.Errorf("get tagname3 err %s",tagName)
	}

	t.Logf("get tag name3 %s", tagName)


}

func TestIsClosingTag(t *testing.T) {
	x:="<a href=\"https://example.com\">"

	isClose := isClosing(x)

	if isClose == true {
		t.Errorf("TestIsClosingTag err  %v",isClose)

	}

	x = "</a>"
	isClose = isClosing(x)
	if isClose == false { 
		t.Errorf("TestIsClosingTag err  %v",isClose)

	}

}


func TestStripQuoteWrap(t *testing.T) {
	x :="'asdfasdfadfafd'"

	result := stripQuoteWrap(x)

	if result != "asdfasdfadfafd" {
		t.Errorf("TestStripQuoteWrap err  %v",result)

	}

	x ="\"asdfasdfadfafd\""

	result = stripQuoteWrap(x)

	if result != "asdfasdfadfafd" {
		t.Errorf("TestStripQuoteWrap err  %v",result)

	}
}






func escapeHtml(input string) string {
	return input
}

func TestParseTag(t *testing.T) {
	xh := "hello<A href=\"#\">www</A>ccc<b><br/>"

	index := 0
	onTag := func(sourcePosition int,position int,tag string,html string, isClosing bool) string {

		// fmt.Printf("...onTag  tagname:%s\n  html:%s",tag,html)

		if index == 0 {
			if tag == "a" && html == "<A href=\"#\">" {
				t.Logf("parse tag success tag:%s html:%s",tag, html)
			} else {
				t.Errorf("parse tag failed")
			}
		}

		if index == 1 {
			if tag == "a" && html == "</A>" {
				t.Logf("parse tag success tag:%s html:%s",tag, html)
			} else {
				t.Errorf("parse tag failed")
			}
		}

		if index == 2 {
			if tag == "b" && html == "<b>" {
				t.Logf("parse tag success tag:%s html:%s",tag, html)
			} else {
				t.Errorf("parse tag failed")
			}
		}

		if index == 3 {
			if tag == "br" && html == "<br/>" {
				t.Logf("parse tag success tag:%s html:%s",tag, html)
			} else {
				t.Errorf("parse tag failed")
			}
		}
	
		index++
		return html
	}

	result := parseTag(xh,onTag,escapeHtml)
	
	if result != xh {
		t.Errorf("parseTag err  %v",result)
		return
	} 
	t.Logf("parseTag %v",result)
}

func TestParseAttr(t *testing.T) {
	xh := "href=\"#\"attr1=b attr2=c attr3 attr4='value4\"'attr5"

	index := 0

	onAttr := func (name string ,value string) string {

 		if index == 0 {
			if name == "href" && value == "#" {
				t.Logf("parse attr success name:%s value:%s",name, value)
			} else {
				t.Errorf("parse attr failed")
			}
		}
		if index == 1 {
			if name == "attr1" && value == "b" {
				t.Logf("parse attr success name:%s value:%s",name, value)
			} else {
				t.Errorf("parse attr failed")
			}
		}
		if index == 2 {
			if name == "attr2" && value == "c" {
				t.Logf("parse attr success name:%s value:%s",name, value)
			} else {
				t.Errorf("parse attr failed")
			}
		}
		if index == 3 {
			if name == "attr3" && value == "" {
				t.Logf("parse attr success name:%s value:%s",name, value)
			} else {
				t.Errorf("parse attr failed")
			}
		}
		if index == 4 {
			if name == "attr4" && value == "value4\"" {
				t.Logf("parse attr success name:%s value:%s",name, value)
			} else {
				t.Errorf("parse attr failed")
			}
		}
		if index == 5 {
			if name == "attr5" && value == "" {
				t.Logf("parse attr success name:%s value:%s",name, value)
			} else {
				t.Errorf("parse attr failed")
			}
		}
		index++
		return name + "=" + value
	}

	result := parseAttr(xh,onAttr)
	
	 
	t.Logf("parseAttr result %v",result)
}
