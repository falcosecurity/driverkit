package modinfo

import (
	"debug/elf"
	"fmt"
	"strings"

	"github.com/mitchellh/mapstructure"
)

type Modinfo struct {
	SrcVersion    string
	Retpoline     string
	Vermagic      string
	Depends       string
	Name          string
	Parm          string
	ParmType      string
	Author        string
	License       string
	KernelVersion string
}

func FromModulePath(modulePath string) (*Modinfo, error) {
	f, err := elf.Open(modulePath)

	if err != nil {
		return nil, fmt.Errorf("error decoding modinfo: %v", err)
	}
	defer f.Close()

	section := f.Section(".modinfo")
	if section == nil {
		return nil, fmt.Errorf("error decoding modinfo: section .modinfo not found")
	}

	data, err := section.Data()
	if err != nil {
		return nil, fmt.Errorf("error decoding modinfo: %v", err)
	}

	res := strMap(strings.Split(string(data), "\x00"), func(v string) string {
		return strings.TrimSpace(v)
	})

	vermagic, ok := res["vermagic"]
	if !ok {
		return nil, fmt.Errorf("error decoding modinfo: vermagic not found in .modinfo")
	}

	versionSplit := strings.Split(vermagic, " ")
	if len(versionSplit) < 1 {
		return nil, fmt.Errorf("error decoding modinfo: kernel version not found in vermagic")
	}
	res["kernelversion"] = strings.TrimSpace(versionSplit[0])

	var info Modinfo
	mapstructure.Decode(res, &info)

	return &info, nil
}

func strMap(vs []string, f func(string) string) map[string]string {
	m := map[string]string{}
	for _, v := range vs {
		arr := strings.Split(v, "=")
		if len(arr) < 2 {
			continue
		}
		m[arr[0]] = f(arr[1])
	}
	return m
}
