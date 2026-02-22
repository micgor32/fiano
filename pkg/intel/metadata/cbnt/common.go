// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

import (
	"strings"

	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

func (Common) TotalSize(p LayoutProvider) uint64 {
	var total uint64
	for _, f := range p.Layout() {
		total += f.Size()
	}
	return total
}

func (Common) OffsetOf(p LayoutProvider, fieldName string) uint64 {
	var offset uint64

	for _, f := range p.Layout() {
		if f.Name == fieldName {
			return offset
		}
		offset += f.Size()
	}

	return 0
}

func (Common) PrettyString(depth uint, withHeader bool, p LayoutProvider, structName string, opts ...pretty.Option) string {
	var lines []string

	if withHeader {
		// FIXME: Passing p here is wrong, let's modify Header to ommit
		// taking obj as an argument, since it is useless if we pass name
		// (which is always the case)
		lines = append(lines, pretty.Header(depth, structName, p))
	}

	for _, f := range p.Layout() {
		lines = append(lines, pretty.SubValue(depth+1, f.Name, "", f.Value, opts...)...)
	}

	if depth < 2 {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}
