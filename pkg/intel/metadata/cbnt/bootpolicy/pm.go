// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
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

type PM struct {
	cbnt.Common
	StructInfo `id:"__PMDA__" version:"0x20" var0:"0" var1:"uint16(s.TotalSize())"`
	Reserved0  [2]byte `require:"0" json:"pcReserved0,omitempty"`
	Data       []byte  `json:"pcData"`
}

// NewPM returns a new instance of PM with
// all default values set.
func NewPM() *PM {
	s := &PM{}
	copy(s.StructInfo.ID[:], []byte(StructureIDPM))
	s.StructInfo.Version = 0x20
	s.Rehash()
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *PM) Validate() error {
	// See tag "require"
	for idx := range s.Reserved0 {
		if s.Reserved0[idx] != 0 {
			return fmt.Errorf("'Reserved0[%d]' is expected to be 0, but it is %v", idx, s.Reserved0[idx])
		}
	}

	return nil
}

func (s *PM) Layout() []cbnt.LayoutField {
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
			ID:   2,
			Name: "Data",
			Size: func() uint64 {
				size := uint64(binary.Size(uint16(0)))
				size += uint64(len(s.Data))
				return size
			},
			Value: func() any { return &s.Data },
			Type:  cbnt.ManifestFieldArrayDynamicWithPrefix,
		},
	}
}

func (s *PM) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("PM: %v", err)
	}

	return ret, nil
}

func (s *PM) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("PM: %v", err)
	}

	return ret, nil
}

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *PM) GetStructInfo() cbnt.StructInfo {
	return s.StructInfo
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *PM) SetStructInfo(newStructInfo cbnt.StructInfo) {
	s.StructInfo = newStructInfo
}

// ReadFrom reads the PM from 'r' in format defined in the document #575623.
func (s *PM) ReadFrom(r io.Reader) (int64, error) {
	return s.Common.ReadFrom(r, s)
}

// ReadDataFrom reads the PM from 'r' excluding StructInfo,
// in format defined in the document #575623.
func (s *PM) ReadDataFrom(r io.Reader) (int64, error) {
	totalN := int64(0)

	// StructInfo (ManifestFieldType: structInfo)
	{
		// ReadDataFrom does not read Struct, use ReadFrom for that.
	}

	// Reserved0 (ManifestFieldType: arrayStatic)
	{
		n, err := 2, binary.Read(r, binary.LittleEndian, s.Reserved0[:])
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'Reserved0': %w", err)
		}
		totalN += int64(n)
	}

	// Data (ManifestFieldType: arrayDynamic)
	{
		var size uint16
		err := binary.Read(r, binary.LittleEndian, &size)
		if err != nil {
			return totalN, fmt.Errorf("unable to the read size of field 'Data': %w", err)
		}
		totalN += int64(binary.Size(size))
		s.Data = make([]byte, size)
		n, err := len(s.Data), binary.Read(r, binary.LittleEndian, s.Data)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'Data': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *PM) RehashRecursive() {
	s.StructInfo.Rehash()
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *PM) Rehash() {
	s.Variable0 = 0
	s.ElementSize = uint16(s.TotalSize())
}

// WriteTo writes the PM into 'w' in format defined in
// the document #575623.
func (s *PM) WriteTo(w io.Writer) (int64, error) {
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
		err := binary.Write(w, binary.LittleEndian, size)
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

// Size returns the total size of the PM.
func (s *PM) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *PM) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return s.Common.PrettyString(depth, withHeader, s, "PM", opts...)
}
