// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

var (
	endianess = binary.LittleEndian
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
		lines = append(lines, pretty.SubValue(depth+1, f.Name, "", f.Value(), opts...)...)
	}

	if depth < 2 {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

func (Common) ReadFrom(r io.Reader, p LayoutProvider) (int64, error) {
	totalN := int64(0)

	for _, f := range p.Layout() {
		switch f.Type {
		case ManifestFieldEndValue:
			totalN, err := readStatic(r, f.Size(), f.Value())
			if err != nil {
				return totalN, fmt.Errorf("unable to read field '%s': %w", f.Name, err)
			}
		case ManifestFieldArrayDynamicWithSize:
			size := uint16(f.Size())
			totalN, err := readArrayDynamic(r, &size, f.Value())
			if err != nil {
				return totalN, fmt.Errorf("unable to read field '%s': %w", f.Name, err)
			}
		case ManifestFieldArrayDynamicWithPrefix:
			totalN, err := readArrayDynamic(r, nil, f.Value())
			if err != nil {
				return totalN, fmt.Errorf("unable to read field '%s': %w", f.Name, err)
			}
		case ManifestFieldList:
			if f.ReadList == nil {
				return totalN, fmt.Errorf("field '%s' has no list reader", f.Name)
			}
			totalN, err := f.ReadList(r)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field '%s': %w", f.Name, err)
			}
		case ManifestFieldArrayStatic:
			totalN, err := readStatic(r, f.Size(), f.Value())
			if err != nil {
				return totalN, fmt.Errorf("unable to read field '%s': %w", f.Name, err)
			}
		case ManifestFieldSubStruct:
			fieldValue := f.Value()
			sub, ok := fieldValue.(io.ReaderFrom)
			if !ok {
				return totalN, fmt.Errorf("field '%s' does not implement io.ReaderFrom", f.Name)
			}
			totalN, err := readSubStruct(r, sub)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field '%s': %w", f.Name, err)
			}
		}
	}

	return totalN, nil
}

// We have 5 possible types of ManifestFieldType:
// endValue, arrayDynamic, arrayStatic, list and subStruct.
// Common.ReadFrom will distingush these and use the helpers.
func readStatic(r io.Reader, fieldSize uint64, fieldValue any) (int64, error) {
	n, err := fieldSize, binary.Read(r, endianess, fieldValue)
	if err != nil {
		return 0, err
	}
	return int64(n), nil
}

func readArrayDynamic(r io.Reader, size *uint16, out any) (int64, error) {
	total := int64(0)

	if size == nil {
		var n uint16
		if err := binary.Read(r, endianess, &n); err != nil {
			return total, err
		}
		total += int64(binary.Size(n))
		size = &n
	}

	dst, ok := out.(*[]byte)
	if !ok {
		return total, fmt.Errorf("arrayDynamic expects *[]byte, got %T", out)
	}

	*dst = make([]byte, *size)
	n := len(*dst)
	if err := binary.Read(r, endianess, *dst); err != nil {
		return total, err
	}
	total += int64(n)

	return total, nil
}

func readSubStruct(r io.Reader, out io.ReaderFrom) (int64, error) {
	n, err := out.ReadFrom(r)
	if err != nil {
		return 0, err
	}
	return n, nil
}
