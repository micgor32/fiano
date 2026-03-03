// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate manifestcodegen

package cbntbootpolicy

import (
	"encoding/binary"
	"fmt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
	"io"
	"math"
	"strings"
	"time"
)

// NewIBBSegment returns a new instance of IBBSegment with
// all default values set.
func NewIBBSegment() *IBBSegment {
	s := &IBBSegment{}
	s.Rehash()
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *IBBSegment) Validate() error {
	// See tag "require"
	for idx := range s.Reserved {
		if s.Reserved[idx] != 0 {
			return fmt.Errorf("'Reserved[%d]' is expected to be 0, but it is %v", idx, s.Reserved[idx])
		}
	}

	return nil
}

func (s *IBBSegment) Layout() []cbnt.LayoutField {
	return []cbnt.LayoutField{
		{
			ID:    0,
			Name:  "Reserved",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.Reserved },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:    1,
			Name:  "Flags",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.Flags },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    2,
			Name:  "Base",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.Base },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    3,
			Name:  "Size",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.Size },
			Type:  cbnt.ManifestFieldEndValue,
		},
	}
}

func (s *IBBSegment) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("IBBSegment: %v", err)
	}

	return ret, nil
}

func (s *IBBSegment) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("IBBSegment: %v", err)
	}

	return ret, nil
}

// ReadFrom reads the IBBSegment from 'r' in format defined in the document #575623.
func (s *IBBSegment) ReadFrom(r io.Reader) (int64, error) {
	totalN := int64(0)

	// Reserved (ManifestFieldType: arrayStatic)
	{
		n, err := 2, binary.Read(r, binary.LittleEndian, s.Reserved[:])
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'Reserved': %w", err)
		}
		totalN += int64(n)
	}

	// Flags (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Read(r, binary.LittleEndian, &s.Flags)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'Flags': %w", err)
		}
		totalN += int64(n)
	}

	// Base (ManifestFieldType: endValue)
	{
		n, err := 4, binary.Read(r, binary.LittleEndian, &s.Base)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'Base': %w", err)
		}
		totalN += int64(n)
	}

	// Size (ManifestFieldType: endValue)
	{
		n, err := 4, binary.Read(r, binary.LittleEndian, &s.Size)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'Size': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *IBBSegment) RehashRecursive() {
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *IBBSegment) Rehash() {
}

// WriteTo writes the IBBSegment into 'w' in format defined in
// the document #575623.
func (s *IBBSegment) WriteTo(w io.Writer) (int64, error) {
	totalN := int64(0)
	s.Rehash()

	// Reserved (ManifestFieldType: arrayStatic)
	{
		n, err := 2, binary.Write(w, binary.LittleEndian, s.Reserved[:])
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'Reserved': %w", err)
		}
		totalN += int64(n)
	}

	// Flags (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Write(w, binary.LittleEndian, &s.Flags)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'Flags': %w", err)
		}
		totalN += int64(n)
	}

	// Base (ManifestFieldType: endValue)
	{
		n, err := 4, binary.Write(w, binary.LittleEndian, &s.Base)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'Base': %w", err)
		}
		totalN += int64(n)
	}

	// Size (ManifestFieldType: endValue)
	{
		n, err := 4, binary.Write(w, binary.LittleEndian, &s.Size)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'Size': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

// ReservedSize returns the size in bytes of the value of field Reserved
func (s *IBBSegment) ReservedTotalSize() uint64 {
	return 2
}

// FlagsSize returns the size in bytes of the value of field Flags
func (s *IBBSegment) FlagsTotalSize() uint64 {
	return 2
}

// BaseSize returns the size in bytes of the value of field Base
func (s *IBBSegment) BaseTotalSize() uint64 {
	return 4
}

// SizeSize returns the size in bytes of the value of field Size
func (s *IBBSegment) SizeTotalSize() uint64 {
	return 4
}

// ReservedOffset returns the offset in bytes of field Reserved
func (s *IBBSegment) ReservedOffset() uint64 {
	return 0
}

// FlagsOffset returns the offset in bytes of field Flags
func (s *IBBSegment) FlagsOffset() uint64 {
	return s.ReservedOffset() + s.ReservedTotalSize()
}

// BaseOffset returns the offset in bytes of field Base
func (s *IBBSegment) BaseOffset() uint64 {
	return s.FlagsOffset() + s.FlagsTotalSize()
}

// SizeOffset returns the offset in bytes of field Size
func (s *IBBSegment) SizeOffset() uint64 {
	return s.BaseOffset() + s.BaseTotalSize()
}

// Size returns the total size of the IBBSegment.
func (s *IBBSegment) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *IBBSegment) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return s.Common.PrettyString(depth, withHeader, s, "IBB Segment", opts...)
}

// NewSE returns a new instance of SE with
// all default values set.
func NewSE(bgv cbnt.BootGuardVersion) *SE {
	var hashAlg cbnt.Algorithm

	s := &SE{}
	copy(s.StructInfo.ID[:], []byte(StructureIDSE))

	if bgv == cbnt.Version10 {
		hashAlg = 0x0b
		s.StructInfo.Version = 0x10
	} else {
		hashAlg = 0x10
		s.StructInfo.Version = 0x20
		// Set through tag "required":
		s.SetNumber = 0
		// Recursively initializing a child structure:
		s.OBBHash = *cbnt.NewHashStructure(hashAlg)
	}

	// Recursively initializing a child structure:
	s.PostIBBHash = *cbnt.NewHashStructure(hashAlg)
	// Recursively initializing a child structure:
	s.DigestList = *cbnt.NewHashList()
	s.Rehash()
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *SE) Validate() error {
	// See tag "require"
	for idx := range s.Reserved0 {
		if s.Reserved0[idx] != 0 {
			return fmt.Errorf("'Reserved0[%d]' is expected to be 0, but it is %v", idx, s.Reserved0[idx])
		}
	}
	// See tag "require"
	if s.SetNumber != 0 {
		return fmt.Errorf("field 'SetNumber' expects value '0', but has %v", s.SetNumber)
	}
	// See tag "require"
	for idx := range s.Reserved1 {
		if s.Reserved1[idx] != 0 {
			return fmt.Errorf("'Reserved1[%d]' is expected to be 0, but it is %v", idx, s.Reserved1[idx])
		}
	}
	// Recursively validating a child structure:
	// TODO: remove later
	// if err := s.PostIBBHash.Validate(); err != nil {
	// 	return fmt.Errorf("error on field 'PostIBBHash': %w", err)
	// }
	// Recursively validating a child structure:
	if err := s.DigestList.Validate(); err != nil {
		return fmt.Errorf("error on field 'DigestList': %w", err)
	}
	// Recursively validating a child structure:
	// TODO: remove later
	// if err := s.OBBHash.Validate(); err != nil {
	// 	return fmt.Errorf("error on field 'OBBHash': %w", err)
	// }
	// See tag "require"
	for idx := range s.Reserved2 {
		if s.Reserved2[idx] != 0 {
			return fmt.Errorf("'Reserved2[%d]' is expected to be 0, but it is %v", idx, s.Reserved2[idx])
		}
	}

	return nil
}

func (s *SE) Layout() []cbnt.LayoutField {
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
			Name:  "Reserved 0",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.Reserved0 },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:    2,
			Name:  "Set Number",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.SetNumber },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    3,
			Name:  "Reserved 1",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.Reserved1 },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:    4,
			Name:  "PBET Value",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.PBETValue },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    5,
			Name:  "Flags",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.Flags },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    6,
			Name:  "IBB MCHBAR",
			Size:  func() uint64 { return 8 },
			Value: func() any { return &s.IBBMCHBAR },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    7,
			Name:  "VT-d BAR",
			Size:  func() uint64 { return 8 },
			Value: func() any { return &s.VTdBAR },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    8,
			Name:  "DMA Protection 0 Base Address",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.DMAProtBase0 },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    9,
			Name:  "DMA Protection 0 Limit Address",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.DMAProtLimit0 },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    10,
			Name:  "DMA Protection 1 Base Address",
			Size:  func() uint64 { return 8 },
			Value: func() any { return &s.DMAProtBase1 },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    11,
			Name:  "DMA Protection 2 Limit Address",
			Size:  func() uint64 { return 8 },
			Value: func() any { return &s.DMAProtLimit1 },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    12,
			Name:  "Post IBB Hash",
			Size:  func() uint64 { return s.PostIBBHash.TotalSize() },
			Value: func() any { return &s.PostIBBHash },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:    13,
			Name:  "IBB Entry Point",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.IBBEntryPoint },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    14,
			Name:  "Digest List",
			Size:  func() uint64 { return s.DigestList.TotalSize() },
			Value: func() any { return &s.DigestList },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:    15,
			Name:  "OBB Hash",
			Size:  func() uint64 { return s.OBBHash.TotalSize() },
			Value: func() any { return &s.OBBHash },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:    16,
			Name:  "Reserved 2",
			Size:  func() uint64 { return 3 },
			Value: func() any { return &s.Reserved2 },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:   17,
			Name: fmt.Sprintf("IBBSegments: Array of \"IBB Segments Element\" of length %d", len(s.IBBSegments)),
			Size: func() uint64 {
				size := uint64(binary.Size(uint8(0)))
				for idx := range s.IBBSegments {
					size += s.IBBSegments[idx].TotalSize()
				}
				return size
			},
			Value: func() any { return &s.IBBSegments },
			Type:  cbnt.ManifestFieldList,
			ReadList: func(r io.Reader) (int64, error) {
				var count uint8
				if err := binary.Read(r, binary.LittleEndian, &count); err != nil {
					return 0, fmt.Errorf("unable to read the count for field 'IBBSegments': %w", err)
				}
				totalN := int64(binary.Size(count))
				s.IBBSegments = make([]IBBSegment, count)
				for idx := range s.IBBSegments {
					n, err := s.IBBSegments[idx].ReadFrom(r)
					if err != nil {
						return totalN, fmt.Errorf("unable to read field 'IBBSegments[%d]': %w", idx, err)
					}
					totalN += int64(n)
				}
				return totalN, nil
			},
		},
	}
}

func (s *SE) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("SE: %v", err)
	}

	return ret, nil
}

func (s *SE) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("SE: %v", err)
	}

	return ret, nil
}

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *SE) GetStructInfo() cbnt.StructInfo {
	return s.StructInfo
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *SE) SetStructInfo(newStructInfo cbnt.StructInfo) {
	s.StructInfo = newStructInfo
}

// ReadFrom reads the SE from 'r' in format defined in the document #575623.
func (s *SE) ReadFrom(r io.Reader) (int64, error) {
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

// ReadDataFrom reads the SE from 'r' excluding StructInfo,
// in format defined in the document #575623.
func (s *SE) ReadDataFrom(r io.Reader) (int64, error) {
	totalN := int64(0)

	// StructInfo (ManifestFieldType: structInfo)
	{
		// ReadDataFrom does not read Struct, use ReadFrom for that.
	}

	// Reserved0 (ManifestFieldType: arrayStatic)
	{
		n, err := 1, binary.Read(r, binary.LittleEndian, s.Reserved0[:])
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'Reserved0': %w", err)
		}
		totalN += int64(n)
	}

	// SetNumber (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Read(r, binary.LittleEndian, &s.SetNumber)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'SetNumber': %w", err)
		}
		totalN += int64(n)
	}

	// Reserved1 (ManifestFieldType: arrayStatic)
	{
		n, err := 1, binary.Read(r, binary.LittleEndian, s.Reserved1[:])
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'Reserved1': %w", err)
		}
		totalN += int64(n)
	}

	// PBETValue (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Read(r, binary.LittleEndian, &s.PBETValue)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'PBETValue': %w", err)
		}
		totalN += int64(n)
	}

	// Flags (ManifestFieldType: endValue)
	{
		n, err := 4, binary.Read(r, binary.LittleEndian, &s.Flags)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'Flags': %w", err)
		}
		totalN += int64(n)
	}

	// IBBMCHBAR (ManifestFieldType: endValue)
	{
		n, err := 8, binary.Read(r, binary.LittleEndian, &s.IBBMCHBAR)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'IBBMCHBAR': %w", err)
		}
		totalN += int64(n)
	}

	// VTdBAR (ManifestFieldType: endValue)
	{
		n, err := 8, binary.Read(r, binary.LittleEndian, &s.VTdBAR)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'VTdBAR': %w", err)
		}
		totalN += int64(n)
	}

	// DMAProtBase0 (ManifestFieldType: endValue)
	{
		n, err := 4, binary.Read(r, binary.LittleEndian, &s.DMAProtBase0)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'DMAProtBase0': %w", err)
		}
		totalN += int64(n)
	}

	// DMAProtLimit0 (ManifestFieldType: endValue)
	{
		n, err := 4, binary.Read(r, binary.LittleEndian, &s.DMAProtLimit0)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'DMAProtLimit0': %w", err)
		}
		totalN += int64(n)
	}

	// DMAProtBase1 (ManifestFieldType: endValue)
	{
		n, err := 8, binary.Read(r, binary.LittleEndian, &s.DMAProtBase1)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'DMAProtBase1': %w", err)
		}
		totalN += int64(n)
	}

	// DMAProtLimit1 (ManifestFieldType: endValue)
	{
		n, err := 8, binary.Read(r, binary.LittleEndian, &s.DMAProtLimit1)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'DMAProtLimit1': %w", err)
		}
		totalN += int64(n)
	}

	// PostIBBHash (ManifestFieldType: subStruct)
	{
		n, err := s.PostIBBHash.ReadFrom(r)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'PostIBBHash': %w", err)
		}
		totalN += int64(n)
	}

	// IBBEntryPoint (ManifestFieldType: endValue)
	{
		n, err := 4, binary.Read(r, binary.LittleEndian, &s.IBBEntryPoint)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'IBBEntryPoint': %w", err)
		}
		totalN += int64(n)
	}

	// DigestList (ManifestFieldType: subStruct)
	{
		n, err := s.DigestList.ReadFrom(r)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'DigestList': %w", err)
		}
		totalN += int64(n)
	}

	// OBBHash (ManifestFieldType: subStruct)
	{
		n, err := s.OBBHash.ReadFrom(r)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'OBBHash': %w", err)
		}
		totalN += int64(n)
	}

	// Reserved2 (ManifestFieldType: arrayStatic)
	{
		n, err := 3, binary.Read(r, binary.LittleEndian, s.Reserved2[:])
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'Reserved2': %w", err)
		}
		totalN += int64(n)
	}

	// IBBSegments (ManifestFieldType: list)
	{
		var count uint8
		err := binary.Read(r, binary.LittleEndian, &count)
		if err != nil {
			return totalN, fmt.Errorf("unable to read the count for field 'IBBSegments': %w", err)
		}
		totalN += int64(binary.Size(count))
		s.IBBSegments = make([]IBBSegment, count)

		for idx := range s.IBBSegments {
			n, err := s.IBBSegments[idx].ReadFrom(r)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field 'IBBSegments[%d]': %w", idx, err)
			}
			totalN += int64(n)
		}
	}

	return totalN, nil
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *SE) RehashRecursive() {
	s.StructInfo.Rehash()
	s.PostIBBHash.Rehash()
	s.DigestList.Rehash()
	s.OBBHash.Rehash()
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *SE) Rehash() {
	s.Variable0 = 0
	s.ElementSize = uint16(s.TotalSize())
}

// WriteTo writes the SE into 'w' in format defined in
// the document #575623.
func (s *SE) WriteTo(w io.Writer) (int64, error) {
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

	// Reserved0 (ManifestFieldType: arrayStatic)
	{
		n, err := 1, binary.Write(w, binary.LittleEndian, s.Reserved0[:])
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'Reserved0': %w", err)
		}
		totalN += int64(n)
	}

	// SetNumber (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Write(w, binary.LittleEndian, &s.SetNumber)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'SetNumber': %w", err)
		}
		totalN += int64(n)
	}

	// Reserved1 (ManifestFieldType: arrayStatic)
	{
		n, err := 1, binary.Write(w, binary.LittleEndian, s.Reserved1[:])
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'Reserved1': %w", err)
		}
		totalN += int64(n)
	}

	// PBETValue (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Write(w, binary.LittleEndian, &s.PBETValue)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'PBETValue': %w", err)
		}
		totalN += int64(n)
	}

	// Flags (ManifestFieldType: endValue)
	{
		n, err := 4, binary.Write(w, binary.LittleEndian, &s.Flags)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'Flags': %w", err)
		}
		totalN += int64(n)
	}

	// IBBMCHBAR (ManifestFieldType: endValue)
	{
		n, err := 8, binary.Write(w, binary.LittleEndian, &s.IBBMCHBAR)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'IBBMCHBAR': %w", err)
		}
		totalN += int64(n)
	}

	// VTdBAR (ManifestFieldType: endValue)
	{
		n, err := 8, binary.Write(w, binary.LittleEndian, &s.VTdBAR)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'VTdBAR': %w", err)
		}
		totalN += int64(n)
	}

	// DMAProtBase0 (ManifestFieldType: endValue)
	{
		n, err := 4, binary.Write(w, binary.LittleEndian, &s.DMAProtBase0)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'DMAProtBase0': %w", err)
		}
		totalN += int64(n)
	}

	// DMAProtLimit0 (ManifestFieldType: endValue)
	{
		n, err := 4, binary.Write(w, binary.LittleEndian, &s.DMAProtLimit0)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'DMAProtLimit0': %w", err)
		}
		totalN += int64(n)
	}

	// DMAProtBase1 (ManifestFieldType: endValue)
	{
		n, err := 8, binary.Write(w, binary.LittleEndian, &s.DMAProtBase1)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'DMAProtBase1': %w", err)
		}
		totalN += int64(n)
	}

	// DMAProtLimit1 (ManifestFieldType: endValue)
	{
		n, err := 8, binary.Write(w, binary.LittleEndian, &s.DMAProtLimit1)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'DMAProtLimit1': %w", err)
		}
		totalN += int64(n)
	}

	// PostIBBHash (ManifestFieldType: subStruct)
	{
		n, err := s.PostIBBHash.WriteTo(w)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'PostIBBHash': %w", err)
		}
		totalN += int64(n)
	}

	// IBBEntryPoint (ManifestFieldType: endValue)
	{
		n, err := 4, binary.Write(w, binary.LittleEndian, &s.IBBEntryPoint)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'IBBEntryPoint': %w", err)
		}
		totalN += int64(n)
	}

	// DigestList (ManifestFieldType: subStruct)
	{
		n, err := s.DigestList.WriteTo(w)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'DigestList': %w", err)
		}
		totalN += int64(n)
	}

	// OBBHash (ManifestFieldType: subStruct)
	{
		n, err := s.OBBHash.WriteTo(w)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'OBBHash': %w", err)
		}
		totalN += int64(n)
	}

	// Reserved2 (ManifestFieldType: arrayStatic)
	{
		n, err := 3, binary.Write(w, binary.LittleEndian, s.Reserved2[:])
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'Reserved2': %w", err)
		}
		totalN += int64(n)
	}

	// IBBSegments (ManifestFieldType: list)
	{
		count := uint8(len(s.IBBSegments))
		err := binary.Write(w, binary.LittleEndian, &count)
		if err != nil {
			return totalN, fmt.Errorf("unable to write the count for field 'IBBSegments': %w", err)
		}
		totalN += int64(binary.Size(count))
		for idx := range s.IBBSegments {
			n, err := s.IBBSegments[idx].WriteTo(w)
			if err != nil {
				return totalN, fmt.Errorf("unable to write field 'IBBSegments[%d]': %w", idx, err)
			}
			totalN += int64(n)
		}
	}

	return totalN, nil
}

// StructInfoSize returns the size in bytes of the value of field StructInfo
func (s *SE) StructInfoTotalSize() uint64 {
	return s.StructInfo.TotalSize()
}

// Reserved0Size returns the size in bytes of the value of field Reserved0
func (s *SE) Reserved0TotalSize() uint64 {
	return 1
}

// SetNumberSize returns the size in bytes of the value of field SetNumber
func (s *SE) SetNumberTotalSize() uint64 {
	return 1
}

// Reserved1Size returns the size in bytes of the value of field Reserved1
func (s *SE) Reserved1TotalSize() uint64 {
	return 1
}

// PBETValueSize returns the size in bytes of the value of field PBETValue
func (s *SE) PBETValueTotalSize() uint64 {
	return 1
}

// FlagsSize returns the size in bytes of the value of field Flags
func (s *SE) FlagsTotalSize() uint64 {
	return 4
}

// IBBMCHBARSize returns the size in bytes of the value of field IBBMCHBAR
func (s *SE) IBBMCHBARTotalSize() uint64 {
	return 8
}

// VTdBARSize returns the size in bytes of the value of field VTdBAR
func (s *SE) VTdBARTotalSize() uint64 {
	return 8
}

// DMAProtBase0Size returns the size in bytes of the value of field DMAProtBase0
func (s *SE) DMAProtBase0TotalSize() uint64 {
	return 4
}

// DMAProtLimit0Size returns the size in bytes of the value of field DMAProtLimit0
func (s *SE) DMAProtLimit0TotalSize() uint64 {
	return 4
}

// DMAProtBase1Size returns the size in bytes of the value of field DMAProtBase1
func (s *SE) DMAProtBase1TotalSize() uint64 {
	return 8
}

// DMAProtLimit1Size returns the size in bytes of the value of field DMAProtLimit1
func (s *SE) DMAProtLimit1TotalSize() uint64 {
	return 8
}

// PostIBBHashSize returns the size in bytes of the value of field PostIBBHash
func (s *SE) PostIBBHashTotalSize() uint64 {
	return s.PostIBBHash.TotalSize()
}

// IBBEntryPointSize returns the size in bytes of the value of field IBBEntryPoint
func (s *SE) IBBEntryPointTotalSize() uint64 {
	return 4
}

// DigestListSize returns the size in bytes of the value of field DigestList
func (s *SE) DigestListTotalSize() uint64 {
	return s.DigestList.TotalSize()
}

// OBBHashSize returns the size in bytes of the value of field OBBHash
func (s *SE) OBBHashTotalSize() uint64 {
	return s.OBBHash.TotalSize()
}

// Reserved2Size returns the size in bytes of the value of field Reserved2
func (s *SE) Reserved2TotalSize() uint64 {
	return 3
}

// IBBSegmentsSize returns the size in bytes of the value of field IBBSegments
func (s *SE) IBBSegmentsTotalSize() uint64 {
	var size uint64
	size += uint64(binary.Size(uint8(0)))
	for idx := range s.IBBSegments {
		size += s.IBBSegments[idx].TotalSize()
	}
	return size
}

// StructInfoOffset returns the offset in bytes of field StructInfo
func (s *SE) StructInfoOffset() uint64 {
	return 0
}

// Reserved0Offset returns the offset in bytes of field Reserved0
func (s *SE) Reserved0Offset() uint64 {
	return s.StructInfoOffset() + s.StructInfoTotalSize()
}

// SetNumberOffset returns the offset in bytes of field SetNumber
func (s *SE) SetNumberOffset() uint64 {
	return s.Reserved0Offset() + s.Reserved0TotalSize()
}

// Reserved1Offset returns the offset in bytes of field Reserved1
func (s *SE) Reserved1Offset() uint64 {
	return s.SetNumberOffset() + s.SetNumberTotalSize()
}

// PBETValueOffset returns the offset in bytes of field PBETValue
func (s *SE) PBETValueOffset() uint64 {
	return s.Reserved1Offset() + s.Reserved1TotalSize()
}

// FlagsOffset returns the offset in bytes of field Flags
func (s *SE) FlagsOffset() uint64 {
	return s.PBETValueOffset() + s.PBETValueTotalSize()
}

// IBBMCHBAROffset returns the offset in bytes of field IBBMCHBAR
func (s *SE) IBBMCHBAROffset() uint64 {
	return s.FlagsOffset() + s.FlagsTotalSize()
}

// VTdBAROffset returns the offset in bytes of field VTdBAR
func (s *SE) VTdBAROffset() uint64 {
	return s.IBBMCHBAROffset() + s.IBBMCHBARTotalSize()
}

// DMAProtBase0Offset returns the offset in bytes of field DMAProtBase0
func (s *SE) DMAProtBase0Offset() uint64 {
	return s.VTdBAROffset() + s.VTdBARTotalSize()
}

// DMAProtLimit0Offset returns the offset in bytes of field DMAProtLimit0
func (s *SE) DMAProtLimit0Offset() uint64 {
	return s.DMAProtBase0Offset() + s.DMAProtBase0TotalSize()
}

// DMAProtBase1Offset returns the offset in bytes of field DMAProtBase1
func (s *SE) DMAProtBase1Offset() uint64 {
	return s.DMAProtLimit0Offset() + s.DMAProtLimit0TotalSize()
}

// DMAProtLimit1Offset returns the offset in bytes of field DMAProtLimit1
func (s *SE) DMAProtLimit1Offset() uint64 {
	return s.DMAProtBase1Offset() + s.DMAProtBase1TotalSize()
}

// PostIBBHashOffset returns the offset in bytes of field PostIBBHash
func (s *SE) PostIBBHashOffset() uint64 {
	return s.DMAProtLimit1Offset() + s.DMAProtLimit1TotalSize()
}

// IBBEntryPointOffset returns the offset in bytes of field IBBEntryPoint
func (s *SE) IBBEntryPointOffset() uint64 {
	return s.PostIBBHashOffset() + s.PostIBBHashTotalSize()
}

// DigestListOffset returns the offset in bytes of field DigestList
func (s *SE) DigestListOffset() uint64 {
	return s.IBBEntryPointOffset() + s.IBBEntryPointTotalSize()
}

// OBBHashOffset returns the offset in bytes of field OBBHash
func (s *SE) OBBHashOffset() uint64 {
	return s.DigestListOffset() + s.DigestListTotalSize()
}

// Reserved2Offset returns the offset in bytes of field Reserved2
func (s *SE) Reserved2Offset() uint64 {
	return s.OBBHashOffset() + s.OBBHashTotalSize()
}

// IBBSegmentsOffset returns the offset in bytes of field IBBSegments
func (s *SE) IBBSegmentsOffset() uint64 {
	return s.Reserved2Offset() + s.Reserved2TotalSize()
}

// Size returns the total size of the SE.
func (s *SE) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *SE) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	base := s.Common.PrettyString(depth, withHeader, s, "IBB Segments Element", opts...)
	var lines []string
	lines = append(lines, base)

	lines = append(lines, pretty.Header(depth+1, fmt.Sprintf("IBBSegments: Array of \"IBB Segments Element\" of length %d", len(s.IBBSegments)), s.IBBSegments))
	for i := 0; i < len(s.IBBSegments); i++ {
		lines = append(lines, fmt.Sprintf("%sitem #%d: ", strings.Repeat("  ", int(depth+2)), i)+strings.TrimSpace(s.IBBSegments[i].PrettyString(depth+2, true)))
	}

	return strings.Join(lines, "\n")
}

// PrettyString returns the bits of the flags in an easy-to-read format.
func (v CachingType) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return v.String()
}

// TotalSize returns the total size measured through binary.Size.
func (v CachingType) TotalSize() uint64 {
	return uint64(binary.Size(v))
}

// WriteTo writes the CachingType into 'w' in binary format.
func (v CachingType) WriteTo(w io.Writer) (int64, error) {
	return int64(v.TotalSize()), binary.Write(w, binary.LittleEndian, v)
}

// ReadFrom reads the CachingType from 'r' in binary format.
func (v CachingType) ReadFrom(r io.Reader) (int64, error) {
	return int64(v.TotalSize()), binary.Read(r, binary.LittleEndian, v)
}

// PrettyString returns the bits of the flags in an easy-to-read format.
func (v PBETValue) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "PBET Value", v))
	}
	lines = append(lines, pretty.SubValue(depth+1, "PBET Value", "", v.PBETValue(), opts...)...)
	return strings.Join(lines, "\n")
}

// TotalSize returns the total size measured through binary.Size.
func (v PBETValue) TotalSize() uint64 {
	return uint64(binary.Size(v))
}

// WriteTo writes the PBETValue into 'w' in binary format.
func (v PBETValue) WriteTo(w io.Writer) (int64, error) {
	return int64(v.TotalSize()), binary.Write(w, binary.LittleEndian, v)
}

// ReadFrom reads the PBETValue from 'r' in binary format.
func (v PBETValue) ReadFrom(r io.Reader) (int64, error) {
	return int64(v.TotalSize()), binary.Read(r, binary.LittleEndian, v)
}

// PrettyString returns the bits of the flags in an easy-to-read format.
func (v SEFlags) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "SE Flags", v))
	}
	lines = append(lines, pretty.SubValue(depth+1, "Reserved 0", "", v.Reserved0(), opts...)...)
	if v.SupportsTopSwapRemediation() {
		lines = append(lines, pretty.SubValue(depth+1, "Supports Top Swap Remediation", "BIOS supports Top Swap remediation action", true, opts...)...)
	} else {
		lines = append(lines, pretty.SubValue(depth+1, "Supports Top Swap Remediation", "BIOS does not support Top Swap remediation action", false, opts...)...)
	}
	if v.TPMFailureLeavesHierarchiesEnabled() {
		lines = append(lines, pretty.SubValue(depth+1, "TPM Failure Leaves Hierarchies Enabled", "Leave Hierarchies enabled. Cap all PCRs on failure.", true, opts...)...)
	} else {
		lines = append(lines, pretty.SubValue(depth+1, "TPM Failure Leaves Hierarchies Enabled", "Do not leave enabled. Disable all Hierarchies or deactivate on failure.", false, opts...)...)
	}
	if v.AuthorityMeasure() {
		lines = append(lines, pretty.SubValue(depth+1, "Authority Measure", "Extend Authority Measurements into the Authority PCR 7", true, opts...)...)
	} else {
		lines = append(lines, pretty.SubValue(depth+1, "Authority Measure", "Do not extend into the Authority PCR 7", false, opts...)...)
	}
	if v.Locality3Startup() {
		lines = append(lines, pretty.SubValue(depth+1, "Locality 3 Startup", "Issue TPM Start-up from Locality 3", true, opts...)...)
	} else {
		lines = append(lines, pretty.SubValue(depth+1, "Locality 3 Startup", "Disabled", false, opts...)...)
	}
	if v.DMAProtection() {
		lines = append(lines, pretty.SubValue(depth+1, "DMA Protection", "Enable DMA Protection", true, opts...)...)
	} else {
		lines = append(lines, pretty.SubValue(depth+1, "DMA Protection", "Disable DMA Protection", false, opts...)...)
	}
	return strings.Join(lines, "\n")
}

// TotalSize returns the total size measured through binary.Size.
func (v SEFlags) TotalSize() uint64 {
	return uint64(binary.Size(v))
}

// WriteTo writes the SEFlags into 'w' in binary format.
func (v SEFlags) WriteTo(w io.Writer) (int64, error) {
	return int64(v.TotalSize()), binary.Write(w, binary.LittleEndian, v)
}

// ReadFrom reads the SEFlags from 'r' in binary format.
func (v SEFlags) ReadFrom(r io.Reader) (int64, error) {
	return int64(v.TotalSize()), binary.Read(r, binary.LittleEndian, v)
}

// PBETValue returns the raw value of the timer setting.
func (pbet PBETValue) PBETValue() uint8 {
	return uint8(pbet) & 0x0f
}

// Duration returns the value as time.Duration.
func (pbet PBETValue) Duration() time.Duration {
	v := pbet.PBETValue()
	if v == 0 {
		return math.MaxInt64
	}
	return time.Second * time.Duration(5+v)
}

// SetDuration sets the value using standard time.Duration as the input.
func (pbet *PBETValue) SetDuration(duration time.Duration) time.Duration {
	v := duration.Nanoseconds()/time.Second.Nanoseconds() - 5
	if v <= 0 {
		v = 1
	}
	if v >= 16 {
		v = 0
	}
	*pbet = PBETValue(v)

	return pbet.Duration()
}

// Reserved0 <TO BE DOCUMENTED>
func (flags SEFlags) Reserved0() uint32 {
	return uint32(flags & 0xffffffe0)
}

// SupportsTopSwapRemediation <TO BE DOCUMENTED>
//
// PrettyString-true:  BIOS supports Top Swap remediation action
// PrettyString-false: BIOS does not support Top Swap remediation action
func (flags SEFlags) SupportsTopSwapRemediation() bool {
	return flags&0x10 != 0
}

// TPMFailureLeavesHierarchiesEnabled <TO BE DOCUMENTED>
//
// PrettyString-true:  Leave Hierarchies enabled. Cap all PCRs on failure.
// PrettyString-false: Do not leave enabled. Disable all Hierarchies or deactivate on failure.
func (flags SEFlags) TPMFailureLeavesHierarchiesEnabled() bool {
	return flags&0x08 != 0
}

// AuthorityMeasure <TO BE DOCUMENTED>
//
// NOTE: PCR[7] is disabled from MTL onwards
//
// PrettyString-true:  Extend Authority Measurements into the Authority PCR 7
// PrettyString-false: Do not extend into the Authority PCR 7
func (flags SEFlags) AuthorityMeasure() bool {
	return flags&0x04 != 0
}

// Locality3Startup <TO BE DOCUMENTED>
//
// PrettyString-true:  Issue TPM Start-up from Locality 3
// PrettyString-false: Disabled
func (flags SEFlags) Locality3Startup() bool {
	return flags&0x02 != 0
}

// DMAProtection <TO BE DOCUMENTED>
//
// PrettyString-true:  Enable DMA Protection
// PrettyString-false: Disable DMA Protection
func (flags SEFlags) DMAProtection() bool {
	return flags&0x01 != 0
}

// String implements fmt.Stringer.
func (c CachingType) String() string {
	switch c {
	case CachingTypeWriteProtect:
		return "write_protect"
	case CachingTypeWriteBack:
		return "write_back"
	case CachingTypeReserved0:
		return "value_0x02"
	case CachingTypeReserved1:
		return "value_0x03"
	}
	return fmt.Sprintf("unexpected_value_0x%02X", uint8(c))
}
