// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbnt

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

// NewHashList returns a new instance of HashList with
// all default values set.
func NewHashList() *HashList {
	s := &HashList{}
	s.Rehash()
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *HashList) Validate() error {
	// See tag "rehashValue"
	{
		expectedValue := uint16(s.Common.TotalSize(s))
		if s.Size != expectedValue {
			return fmt.Errorf("field 'Size' expects write-value '%v', but has %v", expectedValue, s.Size)
		}
	}

	return nil
}

// ReadFrom reads the HashList from 'r' in format defined in the document #575623.
func (s *HashList) ReadFrom(r io.Reader) (int64, error) {
	totalN := int64(0)

	// Size (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Read(r, binary.LittleEndian, &s.Size)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'Size': %w", err)
		}
		totalN += int64(n)
	}

	// List (ManifestFieldType: list)
	{
		var count uint16
		err := binary.Read(r, binary.LittleEndian, &count)
		if err != nil {
			return totalN, fmt.Errorf("unable to read the count for field 'List': %w", err)
		}
		totalN += int64(binary.Size(count))
		s.List = make([]HashStructure, count)

		for idx := range s.List {
			n, err := s.List[idx].ReadFrom(r)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field 'List[%d]': %w", idx, err)
			}
			totalN += int64(n)
		}
	}

	return totalN, nil
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *HashList) RehashRecursive() {
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *HashList) Rehash() {
	s.Size = uint16(s.Common.TotalSize(s))
}

// WriteTo writes the HashList into 'w' in format defined in
// the document #575623.
func (s *HashList) WriteTo(w io.Writer) (int64, error) {
	totalN := int64(0)
	s.Rehash()

	// Size (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Write(w, binary.LittleEndian, &s.Size)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'Size': %w", err)
		}
		totalN += int64(n)
	}

	// List (ManifestFieldType: list)
	{
		count := uint16(len(s.List))
		err := binary.Write(w, binary.LittleEndian, &count)
		if err != nil {
			return totalN, fmt.Errorf("unable to write the count for field 'List': %w", err)
		}
		totalN += int64(binary.Size(count))
		for idx := range s.List {
			n, err := s.List[idx].WriteTo(w)
			if err != nil {
				return totalN, fmt.Errorf("unable to write field 'List[%d]': %w", idx, err)
			}
			totalN += int64(n)
		}
	}

	return totalN, nil
}

func (s *HashList) Layout() []LayoutField {
	return []LayoutField{
		{
			Name:  "Size",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.Size },
		},
		{
			Name: fmt.Sprintf("List: Array of \"Hash List\" of length %d", len(s.List)),
			Size: func() uint64 {
				size := uint64(binary.Size(uint16(0)))
				for idx := range s.List {
					size += s.List[idx].Common.TotalSize(&s.List[idx])
				}
				return size
			},
			Value: func() any { return &s.List },
		},
	}
}

// // SizeSize returns the size in bytes of the value of field Size
// func (s *HashList) SizeTotalSize() uint64 {
// 	return 2
// }
//
// // ListSize returns the size in bytes of the value of field List
// func (s *HashList) ListTotalSize() uint64 {
// 	var size uint64
// 	size += uint64(binary.Size(uint16(0)))
// 	for idx := range s.List {
// 		size += s.List[idx].TotalSize()
// 	}
// 	return size
// }
//
// // SizeOffset returns the offset in bytes of field Size
// func (s *HashList) SizeOffset() uint64 {
// 	return 0
// }
//
// // ListOffset returns the offset in bytes of field List
// func (s *HashList) ListOffset() uint64 {
// 	return s.SizeOffset() + s.SizeTotalSize()
// }
//
// // Size returns the total size of the HashList.
// func (s *HashList) TotalSize() uint64 {
// 	if s == nil {
// 		return 0
// 	}
//
// 	var size uint64
// 	size += s.SizeTotalSize()
// 	size += s.ListTotalSize()
// 	return size
// }

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *HashList) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	result := Common{}.PrettyString(depth, withHeader, s, "Hash List", opts...)
	if depth < 1 {
		return result + "\n"
	}
	return result
}

// NewHashStructure returns a new instance of HashStructure with
// all default values set.
func NewHashStructure(alg Algorithm) *HashStructure {
	s := &HashStructure{}
	// For bg pkg, the default one
	s.HashAlg = alg
	s.Rehash()
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *HashStructure) Validate() error {

	return nil
}

// ReadFrom reads the HashStructure from 'r' in format defined in the document #575623.
func (s *HashStructure) ReadFrom(r io.Reader) (int64, error) {
	totalN := int64(0)

	// HashAlg (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Read(r, binary.LittleEndian, &s.HashAlg)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'HashAlg': %w", err)
		}
		totalN += int64(n)
	}

	// HashBuffer (ManifestFieldType: arrayDynamic)
	{
		var size uint16
		err := binary.Read(r, binary.LittleEndian, &size)
		if err != nil {
			return totalN, fmt.Errorf("unable to the read size of field 'HashBuffer': %w", err)
		}
		totalN += int64(binary.Size(size))
		s.HashBuffer = make([]byte, size)
		n, err := len(s.HashBuffer), binary.Read(r, binary.LittleEndian, s.HashBuffer)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'HashBuffer': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *HashStructure) RehashRecursive() {
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *HashStructure) Rehash() {
}

// WriteTo writes the HashStructure into 'w' in format defined in
// the document #575623.
func (s *HashStructure) WriteTo(w io.Writer) (int64, error) {
	totalN := int64(0)
	s.Rehash()

	// HashAlg (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Write(w, binary.LittleEndian, &s.HashAlg)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'HashAlg': %w", err)
		}
		totalN += int64(n)
	}

	// HashBuffer (ManifestFieldType: arrayDynamic)
	{
		size := uint16(len(s.HashBuffer))
		err := binary.Write(w, binary.LittleEndian, size)
		if err != nil {
			return totalN, fmt.Errorf("unable to write the size of field 'HashBuffer': %w", err)
		}
		totalN += int64(binary.Size(size))
		n, err := len(s.HashBuffer), binary.Write(w, binary.LittleEndian, s.HashBuffer)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'HashBuffer': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

func (s *HashStructure) Layout() []LayoutField {
	return []LayoutField{
		{
			Name:  "Hash Alg",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.HashAlg },
		},
		{
			Name: "Hash Buffer",
			Size: func() uint64 {
				size := uint64(binary.Size(uint16(0)))
				size += uint64(len(s.HashBuffer))
				return size
			},
			Value: func() any { return &s.HashBuffer },
		},
	}
}

// // HashAlgSize returns the size in bytes of the value of field HashAlg
// func (s *HashStructure) HashAlgTotalSize() uint64 {
// 	return 2
// }
//
// // HashBufferSize returns the size in bytes of the value of field HashBuffer
// func (s *HashStructure) HashBufferTotalSize() uint64 {
// 	size := uint64(binary.Size(uint16(0)))
// 	size += uint64(len(s.HashBuffer))
// 	return size
// }
//
// // HashAlgOffset returns the offset in bytes of field HashAlg
// func (s *HashStructure) HashAlgOffset() uint64 {
// 	return 0
// }
//
// // HashBufferOffset returns the offset in bytes of field HashBuffer
// func (s *HashStructure) HashBufferOffset() uint64 {
// 	return s.HashAlgOffset() + s.HashAlgTotalSize()
// }
//
// // Size returns the total size of the HashStructure.
// func (s *HashStructure) TotalSize() uint64 {
// 	if s == nil {
// 		return 0
// 	}
//
// 	var size uint64
// 	size += s.HashAlgTotalSize()
// 	size += s.HashBufferTotalSize()
// 	return size
// }

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *HashStructure) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return Common{}.PrettyString(depth, withHeader, s, "Hash Structure", opts...)
}
