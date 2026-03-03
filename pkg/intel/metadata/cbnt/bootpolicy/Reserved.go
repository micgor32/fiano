// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbntbootpolicy

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

// NewReserved returns a new instance of Reserved with
// all default values set.
func NewReserved() *Reserved {
	s := &Reserved{}
	copy(s.StructInfo.ID[:], []byte(StructureIDReserved))
	s.StructInfo.Version = 0x21
	s.Rehash()
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *Reserved) Validate() error {

	return nil
}

func (s *Reserved) Layout() []cbnt.LayoutField {
	return []cbnt.LayoutField{
		{
			ID:    0,
			Name:  "Struct Info",
			Size:  func() uint64 { return s.StructInfo.TotalSize() },
			Value: func() any { return &s.StructInfo },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:    1,
			Name:  "Reserved Data",
			Size:  func() uint64 { return 32 },
			Value: func() any { return &s.ReservedData },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
	}
}

func (s *Reserved) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("Reserved: %v", err)
	}

	return ret, nil
}

func (s *Reserved) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("Reserved: %v", err)
	}

	return ret, nil
}

// StructureIDReserved is the StructureID (in terms of
// the document #575623) of element 'Reserved'.
const StructureIDReserved = "__PFRS__"

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *Reserved) GetStructInfo() cbnt.StructInfo {
	return s.StructInfo
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *Reserved) SetStructInfo(newStructInfo cbnt.StructInfo) {
	s.StructInfo = newStructInfo
}

// ReadFrom reads the Reserved from 'r' in format defined in the document #575623.
func (s *Reserved) ReadFrom(r io.Reader) (int64, error) {
	var totalN int64

	err := binary.Read(r, binary.LittleEndian, &s.StructInfo)
	if err != nil {
		return totalN, fmt.Errorf("unable to read structure info at %d: %w", totalN, err)
	}
	totalN += int64(binary.Size(s.StructInfo))

	n, err := s.ReadDataFrom(r)
	if err != nil {
		return totalN, fmt.Errorf("unable to read data: %w", err)
	}
	totalN += n

	return totalN, nil
}

// ReadDataFrom reads the Reserved from 'r' excluding StructInfo,
// in format defined in the document #575623.
func (s *Reserved) ReadDataFrom(r io.Reader) (int64, error) {
	totalN := int64(0)

	// StructInfo (ManifestFieldType: structInfo)
	{
		// ReadDataFrom does not read Struct, use ReadFrom for that.
	}

	// ReservedData (ManifestFieldType: arrayStatic)
	{
		n, err := 32, binary.Read(r, binary.LittleEndian, s.ReservedData[:])
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'ReservedData': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *Reserved) RehashRecursive() {
	s.StructInfo.Rehash()
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *Reserved) Rehash() {
	s.Variable0 = 0
	s.ElementSize = uint16(s.TotalSize())
}

// WriteTo writes the Reserved into 'w' in format defined in
// the document #575623.
func (s *Reserved) WriteTo(w io.Writer) (int64, error) {
	totalN := int64(0)
	s.Rehash()

	// StructInfo (ManifestFieldType: structInfo)
	{
		n, err := s.StructInfo.WriteTo(w)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'StructInfo': %w", err)
		}
		totalN += int64(n)
	}

	// ReservedData (ManifestFieldType: arrayStatic)
	{
		n, err := 32, binary.Write(w, binary.LittleEndian, s.ReservedData[:])
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'ReservedData': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

// Size returns the total size of the Reserved.
func (s *Reserved) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *Reserved) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return s.Common.PrettyString(depth, withHeader, s, "Reserved", opts...)
}
