package xss

import (
	"testing"
	// "fmt"

)

func TestParseXss(t *testing.T) {
	x:="<html a='ddd'   x=\"xxxx\">xxxxa<body><body  a='ddd'   x=\"xxxx\"><div>asfasdfasfdas</div></body></html>"

	xss := NewXss()

	result, err := xss.Process(x)

	t.Logf("process result %s %+v", result, err)
}