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

// TPMInfoList represents TPM capabilities supported by ACM
type TPMInfoList struct {
	Common
	Capabilities TPMCapabilities
	Algorithms   []Algorithm
}

// NewTPMInfoList returns a new instance of TPMInfoList with
// all default values set.
func NewTPMInfoList() *TPMInfoList {
	s := &TPMInfoList{}
	s.Rehash()
	return s
}

// ReadFrom reads the TPMInfoList from 'r' in format defined in the document #575623.
func (s *TPMInfoList) ReadFrom(r io.Reader) (int64, error) {
	totalN, err := s.Common.ReadFrom(r, s)
	if err != nil {
		return 0, err
	}

	return totalN, nil
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *TPMInfoList) RehashRecursive() {
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *TPMInfoList) Rehash() {
}

// WriteTo writes the TPMInfoList into 'w' in format defined in
// the document #575623.
func (s *TPMInfoList) WriteTo(w io.Writer) (int64, error) {
	s.Rehash()
	return s.Common.WriteTo(w, s)
}

func (s *TPMInfoList) Layout() []LayoutField {
	return []LayoutField{
		{
			ID:    0,
			Name:  "Capabilities",
			Size:  func() uint64 { return 4 },
			Value: func() any { return &s.Capabilities },
			Type:  ManifestFieldEndValue,
		},
		{
			ID:   1,
			Name: fmt.Sprintf("Algorithms: Array of \"TPM Info List\" of length %d", len(s.Algorithms)),
			Size: func() uint64 {
				size := uint64(binary.Size(uint16(0)))
				for idx := range s.Algorithms {
					size += s.Algorithms[idx].TotalSize()
				}
				return size
			},
			Value: func() any { return &s.Algorithms },
			Type:  ManifestFieldList,
			ReadList: func(r io.Reader) (int64, error) {
				var count uint16
				err := binary.Read(r, binary.LittleEndian, &count)
				if err != nil {
					return 0, fmt.Errorf("unable to read the count for field 'Algorithms': %w", err)
				}
				totalN := int64(binary.Size(count))
				s.Algorithms = make([]Algorithm, count)

				for idx := range s.Algorithms {
					n, err := s.Algorithms[idx].ReadFrom(r)
					if err != nil {
						return totalN, fmt.Errorf("unable to read field 'Algorithms[%d]': %w", idx, err)
					}
					totalN += int64(n)
				}
				return totalN, nil
			},
			WriteList: func(w io.Writer) (int64, error) {
				count := uint16(len(s.Algorithms))
				if err := binary.Write(w, binary.LittleEndian, &count); err != nil {
					return 0, fmt.Errorf("unable to write the count for field 'Algorithms': %w", err)
				}
				totalN := int64(binary.Size(count))

				for idx := range s.Algorithms {
					n, err := s.Algorithms[idx].WriteTo(w)
					if err != nil {
						return totalN, fmt.Errorf("unable to write field 'Algorithms[%d]': %w", idx, err)
					}
					totalN += int64(n)
				}

				return totalN, nil
			},
		},
	}
}

func (s *TPMInfoList) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("HashList: %v", err)
	}

	return ret, nil
}

func (s *TPMInfoList) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("HashList: %v", err)
	}

	return ret, nil
}

func (s *TPMInfoList) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *TPMInfoList) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	result := Common{}.PrettyString(depth, withHeader, s, "TPM Info List", opts...)
	if depth < 1 {
		return result + "\n"
	}
	return result
}

// TPM2PCRExtendPolicySupport defined TPM2 PCR Extend policy support.
type TPM2PCRExtendPolicySupport uint8

// PrettyString returns the bits of the flags in an easy-to-read format.
func (v TPM2PCRExtendPolicySupport) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "TPM 2 PCR Extend Policy Support", v))
	}
	return strings.Join(lines, "\n")
}

// TotalSize returns the total size measured through binary.Size.
func (v TPM2PCRExtendPolicySupport) TotalSize() uint64 {
	return uint64(binary.Size(v))
}

// WriteTo writes the TPM2PCRExtendPolicySupport into 'w' in binary format.
func (v TPM2PCRExtendPolicySupport) WriteTo(w io.Writer) (int64, error) {
	return int64(v.TotalSize()), binary.Write(w, binary.LittleEndian, v)
}

// ReadFrom reads the TPM2PCRExtendPolicySupport from 'r' in binary format.
func (v TPM2PCRExtendPolicySupport) ReadFrom(r io.Reader) (int64, error) {
	return int64(v.TotalSize()), binary.Read(r, binary.LittleEndian, v)
}

// TPMCapabilities defines TPM capabilities
type TPMCapabilities uint32

// PrettyString returns the bits of the flags in an easy-to-read format.
func (v TPMCapabilities) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "TPM Capabilities", v))
	}
	lines = append(lines, pretty.SubValue(depth+1, "TPM 2 PCR Extend Policy Support", "", v.TPM2PCRExtendPolicySupport(), opts...)...)
	lines = append(lines, pretty.SubValue(depth+1, "TPM Family Support", "", v.TPMFamilySupport(), opts...)...)
	return strings.Join(lines, "\n")
}

// TotalSize returns the total size measured through binary.Size.
func (v TPMCapabilities) TotalSize() uint64 {
	return uint64(binary.Size(v))
}

// WriteTo writes the TPMCapabilities into 'w' in binary format.
func (v TPMCapabilities) WriteTo(w io.Writer) (int64, error) {
	return int64(v.TotalSize()), binary.Write(w, binary.LittleEndian, v)
}

// ReadFrom reads the TPMCapabilities from 'r' in binary format.
func (v TPMCapabilities) ReadFrom(r io.Reader) (int64, error) {
	return int64(v.TotalSize()), binary.Read(r, binary.LittleEndian, v)
}

// TPMFamilySupport defines TPM family support
type TPMFamilySupport uint8

// PrettyString returns the bits of the flags in an easy-to-read format.
func (v TPMFamilySupport) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "TPM Family Support", v))
	}
	if v.IsDiscreteTPM12Supported() {
		lines = append(lines, pretty.SubValue(depth+1, "Is Discrete TPM 12 Supported", "Discrete TPM1.2 is supported", true, opts...)...)
	} else {
		lines = append(lines, pretty.SubValue(depth+1, "Is Discrete TPM 12 Supported", "Discrete TPM1.2 is not supported", false, opts...)...)
	}
	if v.IsDiscreteTPM20Supported() {
		lines = append(lines, pretty.SubValue(depth+1, "Is Discrete TPM 20 Supported", "Discrete TPM2.0 is supported", true, opts...)...)
	} else {
		lines = append(lines, pretty.SubValue(depth+1, "Is Discrete TPM 20 Supported", "Discrete TPM2.0 is not supported", false, opts...)...)
	}
	if v.IsFirmwareTPM20Supported() {
		lines = append(lines, pretty.SubValue(depth+1, "Is Firmware TPM 20 Supported", "Firmware TPM2.0 is supported", true, opts...)...)
	} else {
		lines = append(lines, pretty.SubValue(depth+1, "Is Firmware TPM 20 Supported", "Firmware TPM2.0 is not supported", false, opts...)...)
	}
	return strings.Join(lines, "\n")
}

// TotalSize returns the total size measured through binary.Size.
func (v TPMFamilySupport) TotalSize() uint64 {
	return uint64(binary.Size(v))
}

// WriteTo writes the TPMFamilySupport into 'w' in binary format.
func (v TPMFamilySupport) WriteTo(w io.Writer) (int64, error) {
	return int64(v.TotalSize()), binary.Write(w, binary.LittleEndian, v)
}

// ReadFrom reads the TPMFamilySupport from 'r' in binary format.
func (v TPMFamilySupport) ReadFrom(r io.Reader) (int64, error) {
	return int64(v.TotalSize()), binary.Read(r, binary.LittleEndian, v)
}

// IsDiscreteTPM12Supported returns true if discrete TPM1.2 is supported.
// PrettyString-true:  Discrete TPM1.2 is supported
// PrettyString-false: Discrete TPM1.2 is not supported
func (familySupport TPMFamilySupport) IsDiscreteTPM12Supported() bool {
	return familySupport&1 != 0
}

// IsDiscreteTPM20Supported returns true if discrete TPM2.0 is supported.
// PrettyString-true:  Discrete TPM2.0 is supported
// PrettyString-false: Discrete TPM2.0 is not supported
func (familySupport TPMFamilySupport) IsDiscreteTPM20Supported() bool {
	return familySupport&2 != 0
}

// IsFirmwareTPM20Supported returns true if firmware TPM2.0 is supported.
// PrettyString-true:  Firmware TPM2.0 is supported
// PrettyString-false: Firmware TPM2.0 is not supported
func (familySupport TPMFamilySupport) IsFirmwareTPM20Supported() bool {
	return familySupport&(1<<3) != 0
}

// TPM2PCRExtendPolicySupport returns TPM2PCRExtendPolicySupport
func (cap TPMCapabilities) TPM2PCRExtendPolicySupport() TPM2PCRExtendPolicySupport {
	return TPM2PCRExtendPolicySupport(cap & 3)
}

// TPMFamilySupport returns TPMFamilySupport
func (cap TPMCapabilities) TPMFamilySupport() TPMFamilySupport {
	return TPMFamilySupport((cap >> 2) & 15)
}
