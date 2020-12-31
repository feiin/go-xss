package xss

import (
	"testing"
	// "fmt"

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

