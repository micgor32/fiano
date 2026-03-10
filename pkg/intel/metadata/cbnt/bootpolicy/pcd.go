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

// PCD holds various Platform Config Data.
type PCD struct {
	cbnt.Common
	StructInfo `id:"__PCDS__" version:"0x20" var0:"0" var1:"uint16(s.TotalSize())"`
	Reserved0  [2]byte `json:"pcdReserved0,omitempty"`
	SizeOfData [2]byte `json:"pcdSizeOfData,omitempty"`
	Data       []byte  `json:"pcdData"`
}

// NewPCD returns a new instance of PCD with
// all default values set.
func NewPCD() *PCD {
	s := &PCD{}
	// TODO: same as with manifest
	copy(s.StructInfo.(*cbnt.StructInfoCBNT).ID[:], []byte(StructureIDPCD))
	s.StructInfo.(*cbnt.StructInfoCBNT).Version = 0x20
	s.Rehash()
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *PCD) Validate() error {
	return nil
}

func (s *PCD) Layout() []cbnt.LayoutField {
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
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.Reserved0 },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:    2,
			Name:  "Size Of Data",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.SizeOfData },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:   3,
			Name: "Data",
			Size: func() uint64 {
				size := binary.LittleEndian.Uint16(s.SizeOfData[:])
				if size == 0 && len(s.Data) != 0 {
					size = uint16(len(s.Data))
				}
				if s.StructInfo.(*cbnt.StructInfoCBNT).ElementSize != 0 {
					base := s.StructInfo.TotalSize() + 2 + 2
					guessedSize := base + uint64(size)
					if guessedSize != uint64(s.StructInfo.(*cbnt.StructInfoCBNT).ElementSize) {
						size = s.StructInfo.(*cbnt.StructInfoCBNT).ElementSize - uint16(s.StructInfo.TotalSize()) - 2 - 2
					}
				}
				return uint64(size)
			},
			Value: func() any { return &s.Data },
			Type:  cbnt.ManifestFieldArrayDynamicWithSize,
		},
	}
}

func (s *PCD) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("PCD: %v", err)
	}

	return ret, nil
}

func (s *PCD) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("PCD: %v", err)
	}

	return ret, nil
}

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *PCD) GetStructInfo() cbnt.StructInfo {
	return s.StructInfo
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *PCD) SetStructInfo(newStructInfo cbnt.StructInfo) {
	s.StructInfo = newStructInfo
}

// ReadFrom reads the PCD from 'r' in format defined in the document #575623.
func (s *PCD) ReadFrom(r io.Reader, info bool) (int64, error) {
	l := s.Layout()

	if !info {
		l = l[1:]
	}

	return s.Common.ReadFrom(r, cbnt.DummyLayout{Fields: l})

}

// RehashRecursive calls Rehash (see below) recursively.
func (s *PCD) RehashRecursive() {
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *PCD) Rehash() {
	s.StructInfo.(*cbnt.StructInfoCBNT).Variable0 = 0
	s.StructInfo.(*cbnt.StructInfoCBNT).ElementSize = uint16(s.TotalSize())
}

// WriteTo writes the PCD into 'w' in format defined in
// the document #575623.
func (s *PCD) WriteTo(w io.Writer) (int64, error) {
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
		n, err := 2, binary.Write(w, binary.LittleEndian, s.Reserved0[:])
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'Reserved0': %w", err)
		}
		totalN += int64(n)
	}

	// Data (ManifestFieldType: arrayDynamic)
	{
		size := uint16(len(s.Data))
		err := binary.Write(w, binary.LittleEndian, s.SizeOfData)
		if err != nil {
			return totalN, fmt.Errorf("unable to write the size of field 'Data': %w", err)
		}
		totalN += int64(binary.Size(size))
		n, err := len(s.Data), binary.Write(w, binary.LittleEndian, s.Data)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'Data': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

// Size returns the total size of the PCD.
func (s *PCD) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	if s.StructInfo.(*cbnt.StructInfoCBNT).ElementSize != 0 {
		return uint64(s.StructInfo.(*cbnt.StructInfoCBNT).ElementSize)
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *PCD) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return s.Common.PrettyString(depth, withHeader, s, "PCD", opts...)
}
