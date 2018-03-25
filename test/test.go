package main

import (
	"fmt"

	gg "github.com/gobwas/glob"
	"github.com/ryanuber/go-glob"
)

func main() {
	a := glob.Glob("my.host.com", "my.host.com") // true
	fmt.Println(a)
	glob.Glob("Hello,*", "Hello, World!") // true
	glob.Glob("*ello,*", "Hello, World!") // true
	glob.Glob("World!", "Hello, World!")  // false
	res := glob.Glob("/my/*", "/my/path") // true
	fmt.Println(res)
	g := gg.MustCompile("/my/*1")
	res = g.Match("/my/path1")
	fmt.Println(res)
}
