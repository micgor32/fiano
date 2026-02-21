// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

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
