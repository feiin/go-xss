package xss

//spaceIndex get the pos of first space
func spaceIndex(str string) int {

	locs := regSpace.FindStringIndex(str)

	if locs != nil {
		return locs[0]
	}

	return -1
}

//remove html comments
func stripCommentTag(html string) string {
	return regComment.ReplaceAllString(html, "")
}

//remove invisible characters
func stripBlankChar(html string) string {

	chs := []rune(html)

	n := len(chs)

	items := []rune{}
	for i := 0; i < n; i++ {
		ch := chs[i]
		if ch == 127 {
			continue
		}

		if ch <= 13 {
			if ch == 10 || ch == 13 {
				items = append(items, ch)
			}
			continue
		}

		items = append(items, ch)

	}

	return string(items)

}
