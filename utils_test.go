package xss

import (
	"testing"
	// "fmt"
)

func TestSpaceIndex(t *testing.T) {
	x := "<a href=\"https://example.com\">"

	index := spaceIndex(x)

	if index != 2 {
		t.Errorf("index err %+v %d", x, index)
	}

	// t.Logf("space index %+v", index)
}

func TestStripBlankChar(t *testing.T) {
	x := "!---a\u0000\u0001\u0002\u0003\r\n b----" + string(rune(127)) + string(rune(9))

	result := stripBlankChar(x)
	if result != "!---a\r\n b----" {
		t.Errorf("stripBlankChar err %s", result)

	}

}

func TestStripCommentTag(t *testing.T) {
	x := "<a><!-------asfasf ------>sadfasdfsadf</a>"

	result := stripCommentTag(x)

	if result != "<a>sadfasdfsadf</a>" {
		t.Errorf("stripCommentTag err %s", result)

	}

	// t.Logf("stripCommentTag %+v", result)
}
