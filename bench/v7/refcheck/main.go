// refcheck: the v7 ground-truth reference. An implementation INDEPENDENT of Anti-REA's TypeScript
// parsers, built on Go's standard library (debug/elf, debug/pe, debug/macho), of the definitions
// pre-registered in bench/v7/PREREGISTRATION.md §3:
//
//	dwarf     a section named .debug_* / .zdebug_* (ELF, PE) or __debug_* / __zdebug_* or segment __DWARF (Mach-O)
//	locals    ELF: a defined, named STB_LOCAL symbol of type FUNC or OBJECT in .symtab
//	          Mach-O: a named, non-stab, non-external N_SECT symbol other than __mh_*_header
//	          PE: a COFF symbol table with at least one entry
//	debugmap  Mach-O: stabs that name an object file (N_OSO) or a source file (N_SO, not a directory)
//	dsym      Mach-O filetype MH_DSYM
//
// Usage: refcheck <file>...  → one JSON object per line: {"file","format","dwarf","locals","debugmap","dsym"}.
// Fat Mach-O: a property is true when it holds for any slice.
package main

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type facts struct {
	File     string `json:"file"`
	Format   string `json:"format"`
	Dwarf    bool   `json:"dwarf"`
	Locals   bool   `json:"locals"`
	DebugMap bool   `json:"debugmap"`
	Dsym     bool   `json:"dsym"`
	Error    string `json:"error,omitempty"`
}

var dwarfName = regexp.MustCompile(`^(\.z?debug_|__z?debug_)`)
var mhHeader = regexp.MustCompile(`^__mh_\w+_header$`)

const (
	nStab = 0xe0
	nExt  = 0x01
	nType = 0x0e
	nSect = 0x0e
	nSO   = 0x64
	nOSO  = 0x66
)

func machoFacts(f *macho.File, out *facts) {
	if f.Type == 0xa { // MH_DSYM
		out.Dsym = true
	}
	for _, s := range f.Sections {
		if s.Seg == "__DWARF" || dwarfName.MatchString(s.Name) {
			out.Dwarf = true
		}
	}
	for _, l := range f.Loads {
		if seg, ok := l.(*macho.Segment); ok && seg.Name == "__DWARF" {
			out.Dwarf = true
		}
	}
	if f.Symtab == nil {
		return
	}
	for _, s := range f.Symtab.Syms {
		if s.Type&nStab != 0 {
			if (s.Type == nOSO || s.Type == nSO) && s.Name != "" && !strings.HasSuffix(s.Name, "/") {
				out.DebugMap = true
			}
			continue
		}
		if s.Type&nExt == 0 && s.Type&nType == nSect && s.Name != "" && !mhHeader.MatchString(s.Name) {
			out.Locals = true
		}
	}
}

func check(path string) facts {
	out := facts{File: path}
	if f, err := elf.Open(path); err == nil {
		defer f.Close()
		out.Format = "elf"
		for _, s := range f.Sections {
			if dwarfName.MatchString(s.Name) {
				out.Dwarf = true
			}
		}
		syms, _ := f.Symbols() // error when there is no .symtab: no locals
		for _, s := range syms {
			bind, typ := elf.ST_BIND(s.Info), elf.ST_TYPE(s.Info)
			if bind == elf.STB_LOCAL && (typ == elf.STT_FUNC || typ == elf.STT_OBJECT) && s.Section != elf.SHN_UNDEF && s.Name != "" {
				out.Locals = true
			}
		}
		return out
	}
	if f, err := pe.Open(path); err == nil {
		defer f.Close()
		out.Format = "pe"
		for _, s := range f.Sections {
			if dwarfName.MatchString(s.Name) {
				out.Dwarf = true
			}
		}
		out.Locals = f.FileHeader.NumberOfSymbols > 0
		return out
	}
	if f, err := macho.Open(path); err == nil {
		defer f.Close()
		out.Format = "macho"
		machoFacts(f, &out)
		return out
	}
	if ff, err := macho.OpenFat(path); err == nil {
		defer ff.Close()
		out.Format = "macho"
		for _, a := range ff.Arches {
			machoFacts(a.File, &out)
		}
		return out
	}
	out.Format = "other"
	return out
}

func main() {
	enc := json.NewEncoder(os.Stdout)
	for _, p := range os.Args[1:] {
		if err := enc.Encode(check(p)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
