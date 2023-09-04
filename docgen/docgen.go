package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log/slog"
	"os"
	"path"
	"strings"

	"github.com/falcosecurity/driverkit/cmd"
	"github.com/spf13/cobra/doc"
)

const outputDir = "docs"
const websiteTemplate = `---
title: %s
weight: %d
---

`

var (
	targetWebsite    bool
	websitePrepender = func(num int) func(filename string) string {
		total := num
		return func(filename string) string {
			num = num - 1
			title := strings.TrimPrefix(strings.TrimSuffix(strings.ReplaceAll(filename, "_", " "), ".md"), fmt.Sprintf("%s/", outputDir))
			return fmt.Sprintf(websiteTemplate, title, total-num)
		}
	}
	websiteLinker = func(filename string) string {
		if filename == "driverkit.md" {
			return "_index.md"
		}
		return filename
	}
)

// docgen
func main() {
	// Get mode
	flag.BoolVar(&targetWebsite, "website", targetWebsite, "")
	flag.Parse()

	// Get root command
	driverkit := cmd.NewRootCmd()
	root := driverkit.Command()
	num := len(root.Commands()) + 1

	// Setup prepender hook
	prepender := func(num int) func(filename string) string {
		return func(filename string) string {
			return ""
		}
	}
	if targetWebsite {
		prepender = websitePrepender
	}

	// Setup links hook
	linker := func(filename string) string {
		return filename
	}
	if targetWebsite {
		linker = websiteLinker
	}

	// Generate markdown docs
	err := doc.GenMarkdownTreeCustom(root, outputDir, prepender(num), linker)
	if err != nil {
		slog.With("err", err.Error()).Error("markdown generation")
		os.Exit(1)
	}

	if targetWebsite {
		err = os.Rename(path.Join(outputDir, "driverkit.md"), path.Join(outputDir, "_index.md"))
		if err != nil {
			slog.With("err", err.Error()).Error("renaming main docs page")
			os.Exit(1)
		}
	}

	if err = stripSensitive(); err != nil {
		slog.With("err", err.Error()).Error("error replacing sensitive data")
		os.Exit(1)
	}
}

func stripSensitive() error {
	f, err := os.Open(outputDir)
	if err != nil {
		return err
	}
	files, err := f.Readdir(-1)
	f.Close()
	if err != nil {
		return err
	}

	for _, file := range files {
		filePath := path.Join(outputDir, file.Name())
		file, err := ioutil.ReadFile(filePath)
		if err != nil {
			return err
		}

		envMark := []byte{36} // $
		for _, s := range cmd.Sensitive {
			target := []byte(os.Getenv(s))
			file = bytes.ReplaceAll(file, target, append(envMark, []byte(s)...))
		}
		if err = ioutil.WriteFile(filePath, file, 0666); err != nil {
			return err
		}
	}

	return nil
}
