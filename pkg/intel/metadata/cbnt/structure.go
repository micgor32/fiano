// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

// NewStructInfo returns a new instance of StructInfo with
// all default values set.
func NewStructInfo() *StructInfo {
	s := &StructInfo{}
	s.Rehash()
	return s
}

// ReadFrom reads the StructInfo from 'r' in format defined in the document #575623.
func (s *StructInfo) ReadFrom(r io.Reader) (int64, error) {
	totalN, err := s.Common.ReadFrom(r, s)
	if err != nil {
		return 0, err
	}

	return totalN, nil
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *StructInfo) RehashRecursive() {
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *StructInfo) Rehash() {
}

// WriteTo writes the StructInfo into 'w' in format defined in
// the document #575623.
func (s *StructInfo) WriteTo(w io.Writer) (int64, error) {
	totalN := int64(0)
	s.Rehash()

	// ID (ManifestFieldType: arrayStatic)
	{
		n, err := 8, binary.Write(w, binary.LittleEndian, s.ID[:])
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'ID': %w", err)
		}
		totalN += int64(n)
	}

	// Version (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Write(w, binary.LittleEndian, &s.Version)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'Version': %w", err)
		}
		totalN += int64(n)
	}

	// Variable0 (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Write(w, binary.LittleEndian, &s.Variable0)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'Variable0': %w", err)
		}
		totalN += int64(n)
	}

	// ElementSize (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Write(w, binary.LittleEndian, &s.ElementSize)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'ElementSize': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

func (s *StructInfo) Layout() []LayoutField {
	return []LayoutField{
		{
			ID:    0,
			Name:  "ID",
			Size:  func() uint64 { return 8 },
			Value: func() any { return &s.ID },
			Type:  ManifestFieldArrayStatic,
		},
		{
			ID:    1,
			Name:  "Version",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.Version },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    2,
			Name:  "Variable 0",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.Variable0 },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:    3,
			Name:  "Element Size",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.ElementSize },
			Type:  ManifestFieldEndValue,
		},
	}
}

func (s *StructInfo) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("HashList: %v", err)
	}

	return ret, nil
}

func (s *StructInfo) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("HashList: %v", err)
	}

	return ret, nil
}

// Size returns the total size of the StructInfo.
func (s *StructInfo) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *StructInfo) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return Common{}.PrettyString(depth, withHeader, s, "Struct Info", opts...)
}

// StructInfo just returns StructInfo, it is a handy method if StructInfo
// is included anonymously to another type.
func (s StructInfo) StructInfo() StructInfo {
	return s
}

// String returns the ID as a string.
func (s StructureID) String() string {
	return string(s[:])
}
