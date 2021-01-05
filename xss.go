package xss

import (
	// "errors"
	// "bytes"
	// "strings"
	// "io"
)


type Xss struct {

}

//NewXss 
func NewXss() *Xss {
	return &Xss{}
}

//Process 处理xss
func (x *Xss) Process(html string) (string) {

	if len(html) < 3 {
		return html
	}



	return ""
}

