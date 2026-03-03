// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbntbootpolicy

import (
	"fmt"
	"io"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

type Signature struct {
	cbnt.Common
	StructInfo        `id:"__PMSG__" version:"0x20" var0:"0" var1:"0"`
	cbnt.KeySignature `json:"sigKeySignature"`
}

// NewSignature returns a new instance of Signature with
// all default values set.
func NewSignature() *Signature {
	s := &Signature{}
	copy(s.StructInfo.ID[:], []byte(StructureIDSignature))
	s.StructInfo.Version = 0x20
	// Recursively initializing a child structure:
	s.KeySignature = *cbnt.NewKeySignature()
	s.Rehash()
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *Signature) Validate() error {
	// Recursively validating a child structure:
	if err := s.KeySignature.Validate(); err != nil {
		return fmt.Errorf("error on field 'KeySignature': %w", err)
	}

	return nil
}

func (s *Signature) Layout() []cbnt.LayoutField {
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
			Name:  "Key Signature",
			Size:  func() uint64 { return s.KeySignature.TotalSize() },
			Value: func() any { return &s.KeySignature },
			Type:  cbnt.ManifestFieldSubStruct,
		},
	}
}

func (s *Signature) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("Signature: %v", err)
	}

	return ret, nil
}

func (s *Signature) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("Signature: %v", err)
	}

	return ret, nil
}

// GetStructInfo returns current value of StructInfo of the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *Signature) GetStructInfo() cbnt.StructInfo {
	return s.StructInfo
}

// SetStructInfo sets new value of StructInfo to the structure.
//
// StructInfo is a set of standard fields with presented in any element
// ("element" in terms of document #575623).
func (s *Signature) SetStructInfo(newStructInfo cbnt.StructInfo) {
	s.StructInfo = newStructInfo
}

// ReadFrom reads the Signature from 'r' in format defined in the document #575623.
func (s *Signature) ReadFrom(r io.Reader) (int64, error) {
	return s.Common.ReadFrom(r, s)
}

// ReadDataFrom reads the Signature from 'r' excluding StructInfo,
// in format defined in the document #575623.
func (s *Signature) ReadDataFrom(r io.Reader) (int64, error) {
	totalN := int64(0)

	// StructInfo (ManifestFieldType: structInfo)
	{
		// ReadDataFrom does not read Struct, use ReadFrom for that.
	}

	// KeySignature (ManifestFieldType: subStruct)
	{
		n, err := s.KeySignature.ReadFrom(r)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'KeySignature': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *Signature) RehashRecursive() {
	s.StructInfo.Rehash()
	s.KeySignature.Rehash()
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *Signature) Rehash() {
	s.Variable0 = 0
	s.ElementSize = 0
}

// WriteTo writes the Signature into 'w' in format defined in
// the document #575623.
func (s *Signature) WriteTo(w io.Writer) (int64, error) {
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

	// KeySignature (ManifestFieldType: subStruct)
	{
		n, err := s.KeySignature.WriteTo(w)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'KeySignature': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

// Size returns the total size of the Signature.
func (s *Signature) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *Signature) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return s.Common.PrettyString(depth, withHeader, s, "Signature", opts...)
}
