package xss


import (
	"regexp"
	// "fmt"
)

var reg = regexp.MustCompile("\\s|\\n|\\t")

//spaceIndex get the pos of first space
func spaceIndex(str string) int {
	locs := reg.FindStringIndex(str)

	if locs != nil {
		return locs[0]
	}

	return -1
}