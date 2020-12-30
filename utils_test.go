package xss

import (
	"testing"
	// "fmt"

)

func TestSpaceIndex(t *testing.T) {
	x:="<a href=\"https://example.com\">"

	index := spaceIndex(x)

	if index != 2 {
		t.Errorf("index err %+v %d",x,index)
	}

	t.Logf("space index %+v", index)
}