// proto_pollution_scanner: a simple JS prototype pollution detector in Go
// Usage:
//   go run main.go --dir ./src --ext js,ts

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/robertkrimen/otto/parser"
	"github.com/robertkrimen/otto/ast"
)

// visitor holds state while walking AST.
type visitor struct { file string }

// Enter is called before child nodes are visited.
func (v *visitor) Enter(n ast.Node) ast.Visitor {
	switch expr := n.(type) {
	case *ast.MemberExpression:
		// detect obj.__proto__ or obj.constructor.prototype usage
		if id, ok := expr.Property.(*ast.Identifier); ok {
			switch id.Name {
			case "__proto__":
				pos := id.Idx0()
				fmt.Printf("%s:%d:%d prototype access via __proto__\n", v.file, pos.Line, pos.Column)
			case "prototype":
				// check chain: expr.Object should be MemberExpression with constructor
				if inner, ok2 := expr.Object.(*ast.MemberExpression); ok2 {
					if cid, ok3 := inner.Property.(*ast.Identifier); ok3 && cid.Name == "constructor" {
						pos := id.Idx0()
						fmt.Printf("%s:%d:%d prototype access via constructor.prototype\n", v.file, pos.Line, pos.Column)
					}
				}
			}
		}
	case *ast.CallExpression:
		// detect eval()
		if callee, ok := expr.Callee.(*ast.Identifier); ok && callee.Name == "eval" {
			pos := callee.Idx0()
			fmt.Printf("%s:%d:%d call to eval()\n", v.file, pos.Line, pos.Column)
		}
	}
	return v
}

// Exit is required by ast.Visitor but not used.
func (v *visitor) Exit(n ast.Node) {}

func scanFile(path string) {
	src, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading %s: %v\n", path, err)
		return
	}

	prog, err := parser.ParseFile(nil, path, src, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing %s: %v\n", path, err)
		return
	}

	ast.Walk(&visitor{file: path}, prog)
}

func main() {
	// command-line flags
	dir := flag.String("dir", ".", "directory to scan")
	extList := flag.String("ext", "js", "comma-separated file extensions to include (e.g. js,ts)")
	flag.Parse()

	exts := map[string]struct{}{}
	for _, e := range filepath.SplitList(*extList) {
		exts[e] = struct{}{}
	}

	// walk directory
	filepath.Walk(*dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if len(ext) > 0 && ext[1:] != "" {
			if _, ok := exts[ext[1:]]; ok {
				scanFile(path)
			}
		}
		return nil
	})
}

//
//
