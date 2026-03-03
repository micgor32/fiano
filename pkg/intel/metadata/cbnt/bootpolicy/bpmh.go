// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate manifestcodegen

package cbntbootpolicy

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

// NewBPMH returns a new instance of BPMH with
// all default values set.
func NewBPMH() *BPMH {
	s := &BPMH{}
	copy(s.StructInfo.ID[:], []byte(StructureIDBPMH))
	s.StructInfo.Version = 0x23
	s.Rehash()
	return s
}

func (s *BPMH) Layout() []cbnt.LayoutField {
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
			Name:  "Key Signature Offset",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.KeySignatureOffset },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    2,
			Name:  "BPM Revision",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.BPMRevision },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    3,
			Name:  "BPM SVN",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.BPMSVN },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    4,
			Name:  "ACM SVN Auth",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.ACMSVNAuth },
			Type:  cbnt.ManifestFieldEndValue,
		},
		{
			ID:    5,
			Name:  "Reserved 0",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.Reserved0 },
			Type:  cbnt.ManifestFieldArrayStatic,
		},
		{
			ID:    6,
			Name:  "NEM Data Stack",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.NEMDataStack },
			Type:  cbnt.ManifestFieldEndValue,
		},
	}
}

func (s *BPMH) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("BPMH: %v", err)
	}

	return ret, nil
}

func (s *BPMH) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("BPMH: %v", err)
	}

	return ret, nil
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *BPMH) Validate() error {
	// See tag "require"
	for idx := range s.Reserved0 {
		if s.Reserved0[idx] != 0 {
			return fmt.Errorf("'Reserved0[%d]' is expected to be 0, but it is %v", idx, s.Reserved0[idx])
		}
	}

	return nil
}

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *BPMH) GetStructInfo() cbnt.StructInfo {
	return s.StructInfo
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *BPMH) SetStructInfo(newStructInfo cbnt.StructInfo) {
	s.StructInfo = newStructInfo
}

// Okay this might seem bit hacky: we use dummy type that just
// implements LayoutProvider, and based on info value passes
// either full BPMH Layout or BPMH Layout - StructInfo. Not ideal
// but spares 60 lines of boilerplate code.
type dummyLayout struct {
	fields []cbnt.LayoutField
}

func (s dummyLayout) Layout() []cbnt.LayoutField {
	return s.fields
}

// ReadFrom reads the BPMH from 'r' in format defined in the document #575623.
func (s *BPMH) ReadFrom(r io.Reader, info bool) (int64, error) {
	l := s.Layout()

	if !info {
		l = l[1:]
	}

	return s.Common.ReadFrom(r, dummyLayout{fields: l})
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *BPMH) RehashRecursive() {
	s.StructInfo.Rehash()
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *BPMH) Rehash() {
	s.Variable0 = 0x20
	s.ElementSize = uint16(s.TotalSize())
}

// WriteTo writes the BPMH into 'w' in format defined in
// the document #575623.
func (s *BPMH) WriteTo(w io.Writer) (int64, error) {
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

	// KeySignatureOffset (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Write(w, binary.LittleEndian, &s.KeySignatureOffset)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'KeySignatureOffset': %w", err)
		}
		totalN += int64(n)
	}

	// BPMRevision (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Write(w, binary.LittleEndian, &s.BPMRevision)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'BPMRevision': %w", err)
		}
		totalN += int64(n)
	}

	// BPMSVN (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Write(w, binary.LittleEndian, &s.BPMSVN)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'BPMSVN': %w", err)
		}
		totalN += int64(n)
	}

	// ACMSVNAuth (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Write(w, binary.LittleEndian, &s.ACMSVNAuth)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'ACMSVNAuth': %w", err)
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

	// NEMDataStack (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Write(w, binary.LittleEndian, &s.NEMDataStack)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'NEMDataStack': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

// Size returns the total size of the BPMH.
func (s *BPMH) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *BPMH) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return s.Common.PrettyString(depth, withHeader, s, "BPMH", opts...)
}

// InBytes returns the size in bytes.
func (s Size4K) InBytes() uint32 {
	return uint32(s) * 4096
}

// NewSize4K returns the given size as multiple of 4K
func NewSize4K(size uint32) Size4K {
	return Size4K(size / 4096)
}

// PrettyString returns the bits of the flags in an easy-to-read format.
func (v Size4K) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "Size 4 K", v))
	}
	lines = append(lines, pretty.SubValue(depth+1, "In Bytes", "", v.InBytes(), opts...)...)
	return strings.Join(lines, "\n")
}

// TotalSize returns the total size measured through binary.Size.
func (v Size4K) TotalSize() uint64 {
	return uint64(binary.Size(v))
}

// WriteTo writes the Size4K into 'w' in binary format.
func (v Size4K) WriteTo(w io.Writer) (int64, error) {
	return int64(v.TotalSize()), binary.Write(w, binary.LittleEndian, v)
}

// ReadFrom reads the Size4K from 'r' in binary format.
func (v Size4K) ReadFrom(r io.Reader) (int64, error) {
	return int64(v.TotalSize()), binary.Read(r, binary.LittleEndian, v)
}
