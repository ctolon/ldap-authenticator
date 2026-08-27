// Command doccheck reports exported API with no doc comment.
//
//	go run ./internal/tools/doccheck .
//
// staticcheck's ST1020 and friends check that a doc comment is *shaped*
// correctly; nothing in the standard toolchain checks that one exists. For
// a library, the exported surface is the documentation, and a symbol
// somebody has to read the implementation to use is a symbol that is not
// finished.
//
// What it looks at: exported functions, exported types, the exported
// fields of exported structs, the methods of exported interfaces, exported
// constants and variables, and methods on exported types.
//
// What it ignores: tests, testdata, vendored trees, anything unexported —
// including methods on unexported types, which are not API however they
// are spelled — and package main, which has no importable surface at all.
// A command's exported identifiers are exported only because Go has no
// other spelling for "used by another file in this package".
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	flag.Parse()

	roots := flag.Args()
	if len(roots) == 0 {
		roots = []string{"."}
	}

	var findings []string

	for _, root := range roots {
		found, err := check(root)
		if err != nil {
			fmt.Fprintln(os.Stderr, "doccheck:", err)
			os.Exit(2)
		}

		findings = append(findings, found...)
	}

	for _, finding := range findings {
		fmt.Println(finding)
	}

	if len(findings) > 0 {
		fmt.Fprintf(os.Stderr, "\n%d exported declarations have no doc comment\n", len(findings))
		os.Exit(1)
	}
}

func check(root string) ([]string, error) {
	var findings []string

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case entry.IsDir():
			// Vendored and generated trees are somebody else's problem,
			// and testdata is not compiled.
			if name := entry.Name(); name == "vendor" || name == "testdata" || name == ".git" {
				return filepath.SkipDir
			}

			return nil
		case !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go"):
			return nil
		}

		fset := token.NewFileSet()

		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}

		// A command exports nothing that anybody can import.
		if file.Name.Name == "main" {
			return nil
		}

		findings = append(findings, checkFile(fset, file)...)

		return nil
	})

	return findings, err
}

func checkFile(fset *token.FileSet, file *ast.File) []string {
	var findings []string

	report := func(pos token.Pos, format string, args ...any) {
		findings = append(findings,
			fmt.Sprintf("%s: %s has no doc comment", fset.Position(pos), fmt.Sprintf(format, args...)))
	}

	for _, decl := range file.Decls {
		switch decl := decl.(type) {
		case *ast.FuncDecl:
			if !decl.Name.IsExported() || decl.Doc != nil {
				continue
			}

			// A method on an unexported type is not API, whatever its own
			// name says.
			if decl.Recv != nil && !exportedReceiver(decl.Recv) {
				continue
			}

			report(decl.Pos(), "func %s", decl.Name.Name)

		case *ast.GenDecl:
			if decl.Tok == token.IMPORT {
				continue
			}

			findings = append(findings, checkGenDecl(fset, decl)...)
		}
	}

	return findings
}

func checkGenDecl(fset *token.FileSet, decl *ast.GenDecl) []string {
	var findings []string

	report := func(pos token.Pos, format string, args ...any) {
		findings = append(findings,
			fmt.Sprintf("%s: %s has no doc comment", fset.Position(pos), fmt.Sprintf(format, args...)))
	}

	for _, spec := range decl.Specs {
		switch spec := spec.(type) {
		case *ast.TypeSpec:
			if !spec.Name.IsExported() {
				continue
			}

			if spec.Doc == nil && decl.Doc == nil {
				report(spec.Pos(), "type %s", spec.Name.Name)
			}

			switch underlying := spec.Type.(type) {
			case *ast.StructType:
				for _, field := range underlying.Fields.List {
					for _, name := range field.Names {
						if name.IsExported() && field.Doc == nil {
							report(name.Pos(), "field %s.%s", spec.Name.Name, name.Name)
						}
					}
				}

			case *ast.InterfaceType:
				for _, method := range underlying.Methods.List {
					for _, name := range method.Names {
						if method.Doc == nil {
							report(name.Pos(), "method %s.%s", spec.Name.Name, name.Name)
						}
					}
				}
			}

		case *ast.ValueSpec:
			// A grouped declaration may be documented as a group, as a
			// block of sentinel errors usually is.
			if decl.Doc != nil || spec.Doc != nil {
				continue
			}

			for _, name := range spec.Names {
				if name.IsExported() {
					report(name.Pos(), "%s", name.Name)
				}
			}
		}
	}

	return findings
}

func exportedReceiver(recv *ast.FieldList) bool {
	if len(recv.List) == 0 {
		return false
	}

	expr := recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}

	if index, ok := expr.(*ast.IndexExpr); ok {
		expr = index.X
	}

	ident, ok := expr.(*ast.Ident)

	return ok && ident.IsExported()
}
