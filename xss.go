package xss

import (
	"golang.org/x/net/html"
	"errors"
	"bytes"
	"strings"
	"io"
)


type Xss struct {

}

//NewXss 
func NewXss() *Xss {
	return &Xss{}
}

//Process 处理xss
func (x *Xss) Process(htmlContent string) (string, error) {

	doc, _ := html.Parse(strings.NewReader(htmlContent))
   
    body := renderNode(doc)
    return body,nil

}



func getBody(doc *html.Node) (*html.Node, error) {
    var b *html.Node
    var f func(*html.Node)
    f = func(n *html.Node) {
        if n.Type == html.ElementNode && n.Data == "html" {
            b = n
        }
        for c := n.FirstChild; c != nil; c = c.NextSibling {
            f(c)
        }
    }
    f(doc)
    if b != nil {
        return b, nil
    }
    return nil, errors.New("Missing <body> in the node tree")
}

func renderNode(n *html.Node) string {
    var buf bytes.Buffer
    w := io.Writer(&buf)
    html.Render(w, n)
    return buf.String()
}
