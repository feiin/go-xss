package xss

import (
	"testing"
	// "fmt"
)

func TestEscapeHtmlEntities(t *testing.T) {

	str := "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>"

	result := escapeHTMLEntities(str)

	if result != "<IMG SRC=javascript:alert('XSS')>" {
		t.Errorf("EscapeHtmlEntities err %s", result)
	}

	str = "<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>"
	result = escapeHTMLEntities(str)

	if result != "<IMG SRC=javascript:alert('XSS')>" {
		t.Errorf("EscapeHtmlEntities err %s", result)
	}

	str = "<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>"
	result = escapeHTMLEntities(str)

	if result != "<IMG SRC=javascript:alert('XSS')>" {
		t.Errorf("EscapeHtmlEntities err %s", result)
	}
}

func TestNewXssOption(t *testing.T) {

	o := NewXssOption()
	if o.StripBlankChar != false {
		t.Errorf("TestNewXssOption err")

	}

	if o.AllowCommentTag != false {
		t.Errorf("TestNewXssOption err")

	}

	if o.StripIgnoreTag != false {
		t.Errorf("TestNewXssOption err")

	}
}

func TestNewDefaultXssOption(t *testing.T) {
	o := NewDefaultXssOption()

	if o.StripIgnoreTag != false {
		t.Errorf("TestNewDefaultXssOption err")

	}

	if o.WhiteList == nil {
		t.Errorf("TestNewDefaultXssOption err")
	}

	if o.OnTag == nil {
		t.Errorf("TestNewDefaultXssOption err")
	}
}

func TestIsSafeLink(t *testing.T) {
	source := "ftp://"

	result := isSafeLinkValue(source)

	if result != true {
		t.Errorf("TestIsSafeLink err %v", result)

	}

	source = "./"

	result = isSafeLinkValue(source)

	if result != true {
		t.Errorf("TestIsSafeLink err")

	}

	source = "../"

	result = isSafeLinkValue(source)

	if result != true {
		t.Errorf("TestIsSafeLink err")

	}
}

func TestEscapeHTMLEntities1(t *testing.T) {
	source := "&#d"
	result := escapeHTMLEntities(source)
	if result != "" {
		t.Errorf("escapeHTMLEntities err")

	}

	source = "&#d;"
	result = escapeHTMLEntities(source)
	if result != "" {
		t.Errorf("escapeHTMLEntities err")

	}

	source = "&#xX;"
	result = escapeHTMLEntities(source)
	if result != "" {
		t.Errorf("escapeHTMLEntities3 err%v;", result)

	}
}


func TestStripTagBody(t *testing.T) {
	r := stripTagBody([]string{},nil)
	html := ""

	result := r.Remove(html)

	if result != "" {
		t.Errorf("TestStripTagBodyResultRemove err;")

	}
}