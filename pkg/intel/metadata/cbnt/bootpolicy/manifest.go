// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate manifestcodegen

package cbntbootpolicy

import (
	"bytes"
	"fmt"

	"encoding/binary"
	"io"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"

	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	"github.com/linuxboot/fiano/pkg/uefi"
)

// NewManifest returns a new instance of Manifest with
// all default values set.
func NewManifest() *Manifest {
	s := &Manifest{}
	// Recursively initializing a child structure:
	s.BPMH = *NewBPMH()
	// Recursively initializing a child structure:
	s.PMSE = *NewSignature()
	s.Rehash()
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *Manifest) Validate() error {
	// Recursively validating a child structure:
	if err := s.BPMH.Validate(); err != nil {

		return fmt.Errorf("error on field 'BPMH': %w", err)
	}
	spew.Dump(s.BPMH)
	spew.Dump(BPMH(s.rehashedBPMH()))

	// See tag "rehashValue"
	{
		expectedValue := BPMH(s.rehashedBPMH())
		if s.BPMH != expectedValue {
			return fmt.Errorf("field 'BPMH' expects write-value '%v', but has %v", expectedValue, s.BPMH)
		}
	}
	// Recursively validating a child structure:
	if err := s.PMSE.Validate(); err != nil {
		return fmt.Errorf("error on field 'PMSE': %w", err)
	}

	return nil
}

// fieldIndexByStructID returns the position index within
// structure Manifest of the field by its StructureID
// (see document #575623, an example of StructureID value is "__KEYM__").
func (_ Manifest) fieldIndexByStructID(structID string) int {
	switch structID {
	case StructureIDBPMH:
		return 0
	case StructureIDSE:
		return 1
	case StructureIDTXT:
		return 2
	case StructureIDReserved:
		return 3
	case StructureIDPCD:
		return 4
	case StructureIDPM:
		return 5
	case StructureIDSignature:
		return 6
	}

	return -1
}

// fieldNameByIndex returns the name of the field by its position number
// within structure Manifest.
func (_ Manifest) fieldNameByIndex(fieldIndex int) string {
	switch fieldIndex {
	case 0:
		return "BPMH"
	case 1:
		return "SE"
	case 2:
		return "TXTE"
	case 3:
		return "Res"
	case 4:
		return "PCDE"
	case 5:
		return "PME"
	case 6:
		return "PMSE"
	}

	return fmt.Sprintf("invalidFieldIndex_%d", fieldIndex)
}

func (s *Manifest) Layout() []cbnt.LayoutField {
	return []cbnt.LayoutField{
		{
			ID:    0,
			Name:  "BPMH: Header",
			Size:  func() uint64 { return s.BPMH.TotalSize() },
			Value: func() any { return &s.BPMH },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:   1,
			Name: fmt.Sprintf("SE: Array of \"Boot Policy Manifest\" of length %d", len(s.SE)),
			Size: func() uint64 {
				var size uint64
				for idx := range s.SE {
					size += s.SE[idx].TotalSize()
				}
				return size
			},
			Value: func() any { return &s.SE },
			Type:  cbnt.ManifestFieldList,
		},
		{
			ID:   2,
			Name: "TXTE",
			Size: func() uint64 {
				if s.TXTE == nil {
					return 0
				}
				return s.TXTE.TotalSize()
			},
			Value: func() any { return s.TXTE },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:   3,
			Name: "Res",
			Size: func() uint64 {
				if s.Res == nil {
					return 0
				}
				return s.Res.TotalSize()
			},
			Value: func() any { return s.Res },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:   4,
			Name: "PCDE: Platform Config Data",
			Size: func() uint64 {
				if s.PCDE == nil {
					return 0
				}
				return s.PCDE.TotalSize()
			},
			Value: func() any { return s.PCDE },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:   5,
			Name: "PME: Platform Manufacturer",
			Size: func() uint64 {
				if s.PME == nil {
					return 0
				}
				return s.PME.TotalSize()
			},
			Value: func() any { return s.PME },
			Type:  cbnt.ManifestFieldSubStruct,
		},
		{
			ID:    6,
			Name:  "PMSE: Signature",
			Size:  func() uint64 { return s.PMSE.TotalSize() },
			Value: func() any { return &s.PMSE },
			Type:  cbnt.ManifestFieldSubStruct,
		},
	}
}

func (s *Manifest) SizeOf(id int) (uint64, error) {
	ret, err := s.Common.SizeOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("Manifest: %v", err)
	}

	return ret, nil
}

func (s *Manifest) OffsetOf(id int) (uint64, error) {
	ret, err := s.Common.OffsetOf(s, id)
	if err != nil {
		return ret, fmt.Errorf("Manifest: %v", err)
	}

	return ret, nil
}

// ReadFrom reads the Manifest from 'r' in format defined in the document #575623.
func (s *Manifest) ReadFrom(r io.Reader) (returnN int64, returnErr error) {
	var missingFieldsByIndices = [7]bool{
		0: true,
		6: true,
	}
	defer func() {
		if returnErr != nil {
			return
		}
		for fieldIndex, v := range missingFieldsByIndices {
			if v {
				returnErr = fmt.Errorf("field '%s' is missing", s.fieldNameByIndex(fieldIndex))
				break
			}
		}
	}()
	var totalN int64
	previousFieldIndex := int(-1)
	for {
		var structInfo cbnt.StructInfo
		err := binary.Read(r, binary.LittleEndian, &structInfo)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return totalN, nil
		}
		if err != nil {
			return totalN, fmt.Errorf("unable to read structure info at %d: %w", totalN, err)
		}
		totalN += int64(binary.Size(structInfo))

		structID := structInfo.ID.String()
		fieldIndex := s.fieldIndexByStructID(structID)
		if fieldIndex < 0 {
			// TODO: report error "unknown structure ID: '"+structID+"'"
			continue
		}
		if cbnt.StrictOrderCheck && fieldIndex < previousFieldIndex {
			return totalN, fmt.Errorf("invalid order of fields (%d < %d): structure '%s' is out of order", fieldIndex, previousFieldIndex, structID)
		}
		missingFieldsByIndices[fieldIndex] = false

		var n int64
		switch structID {
		case StructureIDBPMH:
			if fieldIndex == previousFieldIndex {
				return totalN, fmt.Errorf("field 'BPMH' is not a slice, but multiple elements found")
			}
			s.BPMH.SetStructInfo(structInfo)
			n, err = s.BPMH.ReadDataFrom(r)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field BPMH at %d: %w", totalN, err)
			}
		case StructureIDSE:
			var el SE
			el.SetStructInfo(structInfo)
			n, err = el.ReadDataFrom(r)
			s.SE = append(s.SE, el)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field SE at %d: %w", totalN, err)
			}
		case StructureIDTXT:
			if fieldIndex == previousFieldIndex {
				return totalN, fmt.Errorf("field 'TXTE' is not a slice, but multiple elements found")
			}
			s.TXTE = &TXT{}
			s.TXTE.SetStructInfo(structInfo)
			n, err = s.TXTE.ReadDataFrom(r)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field TXTE at %d: %w", totalN, err)
			}
		case StructureIDReserved:
			if fieldIndex == previousFieldIndex {
				return totalN, fmt.Errorf("field 'Res' is not a slice, but multiple elements found")
			}
			s.Res = &Reserved{}
			s.Res.SetStructInfo(structInfo)
			n, err = s.Res.ReadDataFrom(r)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field Res at %d: %w", totalN, err)
			}
		case StructureIDPCD:
			if fieldIndex == previousFieldIndex {
				return totalN, fmt.Errorf("field 'PCDE' is not a slice, but multiple elements found")
			}
			s.PCDE = &PCD{}
			s.PCDE.SetStructInfo(structInfo)
			n, err = s.PCDE.ReadDataFrom(r)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field PCDE at %d: %w", totalN, err)
			}
		case StructureIDPM:
			if fieldIndex == previousFieldIndex {
				return totalN, fmt.Errorf("field 'PME' is not a slice, but multiple elements found")
			}
			s.PME = &PM{}
			s.PME.SetStructInfo(structInfo)
			n, err = s.PME.ReadDataFrom(r)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field PME at %d: %w", totalN, err)
			}
		case StructureIDSignature:
			if fieldIndex == previousFieldIndex {
				return totalN, fmt.Errorf("field 'PMSE' is not a slice, but multiple elements found")
			}
			s.PMSE.SetStructInfo(structInfo)
			n, err = s.PMSE.ReadDataFrom(r)
			if err != nil {
				return totalN, fmt.Errorf("unable to read field PMSE at %d: %w", totalN, err)
			}
		default:
			return totalN, fmt.Errorf("there is no field with structure ID '%s' in Manifest", structInfo.ID)
		}
		totalN += n
		previousFieldIndex = fieldIndex
	}
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *Manifest) RehashRecursive() {
	s.BPMH.Rehash()
	if s.TXTE != nil {
		s.TXTE.Rehash()
	}
	if s.Res != nil {
		s.Res.Rehash()
	}
	if s.PCDE != nil {
		s.PCDE.Rehash()
	}
	if s.PME != nil {
		s.PME.Rehash()
	}
	s.PMSE.Rehash()
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *Manifest) Rehash() {
	s.BPMH = BPMH(s.rehashedBPMH())
}

// WriteTo writes the Manifest into 'w' in format defined in
// the document #575623.
func (s *Manifest) WriteTo(w io.Writer) (int64, error) {
	totalN := int64(0)
	s.Rehash()

	// BPMH (ManifestFieldType: element)
	{
		n, err := s.BPMH.WriteTo(w)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'BPMH': %w", err)
		}
		totalN += int64(n)
	}

	// SE (ManifestFieldType: elementList)
	{
		for idx := range s.SE {
			n, err := s.SE[idx].WriteTo(w)
			if err != nil {
				return totalN, fmt.Errorf("unable to write field 'SE[%d]': %w", idx, err)
			}
			totalN += int64(n)
		}
	}

	// TXTE (ManifestFieldType: element)
	if s.TXTE != nil {
		n, err := s.TXTE.WriteTo(w)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'TXTE': %w", err)
		}
		totalN += int64(n)
	}

	// Res (ManifestFieldType: element)
	if s.Res != nil {
		n, err := s.Res.WriteTo(w)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'Res': %w", err)
		}
		totalN += int64(n)
	}

	// PCDE (ManifestFieldType: element)
	if s.PCDE != nil {
		n, err := s.PCDE.WriteTo(w)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'PCDE': %w", err)
		}
		totalN += int64(n)
	}

	// PME (ManifestFieldType: element)
	if s.PME != nil {
		n, err := s.PME.WriteTo(w)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'PME': %w", err)
		}
		totalN += int64(n)
	}

	// PMSE (ManifestFieldType: element)
	{
		n, err := s.PMSE.WriteTo(w)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'PMSE': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

// Size returns the total size of the Manifest.
func (s *Manifest) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	return s.Common.TotalSize(s)
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *Manifest) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "Boot Policy Manifest", s))
	}
	if s == nil {
		return strings.Join(lines, "\n")
	}
	// ManifestFieldType is element
	lines = append(lines, pretty.SubValue(depth+1, "BPMH: Header", "", &s.BPMH, opts...)...)
	// ManifestFieldType is elementList
	lines = append(lines, pretty.Header(depth+1, fmt.Sprintf("SE: Array of \"Boot Policy Manifest\" of length %d", len(s.SE)), s.SE))
	for i := 0; i < len(s.SE); i++ {
		lines = append(lines, fmt.Sprintf("%sitem #%d: ", strings.Repeat("  ", int(depth+2)), i)+strings.TrimSpace(s.SE[i].PrettyString(depth+2, true)))
	}
	if depth < 1 {
		lines = append(lines, "")
	}
	// ManifestFieldType is element
	lines = append(lines, pretty.SubValue(depth+1, "TXTE", "", s.TXTE, opts...)...)
	// ManifestFieldType is element
	lines = append(lines, pretty.SubValue(depth+1, "Res", "", s.Res, opts...)...)
	// ManifestFieldType is element
	lines = append(lines, pretty.SubValue(depth+1, "PCDE: Platform Config Data", "", s.PCDE, opts...)...)
	// ManifestFieldType is element
	lines = append(lines, pretty.SubValue(depth+1, "PME: Platform Manufacturer", "", s.PME, opts...)...)
	// ManifestFieldType is element
	lines = append(lines, pretty.SubValue(depth+1, "PMSE: Signature", "", &s.PMSE, opts...)...)
	if depth < 2 {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

// StructInfo is the information about how to parse the structure.
func (bpm Manifest) StructInfo() StructInfo {
	return bpm.BPMH.StructInfo
}

// ValidateIBB returns an error if IBB segments does not match the signature
func (bpm *Manifest) ValidateIBB(firmware uefi.Firmware) error {
	if len(bpm.SE[0].DigestList.List) == 0 {
		return fmt.Errorf("no IBB hashes")
	}

	digest := bpm.SE[0].DigestList.List[0] // [0] instead of range -- is intentionally

	h, err := digest.HashAlg.Hash()
	if err != nil {
		return fmt.Errorf("invalid hash function: %v", digest.HashAlg)
	}

	for _, _range := range bpm.IBBDataRanges(uint64(len(firmware.Buf()))) {
		if _, err := h.Write(firmware.Buf()[_range.Offset:_range.End()]); err != nil {
			return fmt.Errorf("unable to hash: %w", err)
		}
	}
	hashValue := h.Sum(nil)

	if !bytes.Equal(hashValue, digest.HashBuffer) {
		return fmt.Errorf("IBB %s hash mismatch: %X != %X", digest.HashAlg, hashValue, digest.HashBuffer)
	}

	return nil
}

// IBBDataRanges returns data ranges of IBB.
func (bpm *Manifest) IBBDataRanges(firmwareSize uint64) pkgbytes.Ranges {
	var result pkgbytes.Ranges

	for _, seg := range bpm.SE[0].IBBSegments {
		if seg.Flags&1 == 1 {
			continue
		}
		startIdx := calculateOffsetFromPhysAddr(uint64(seg.Base), firmwareSize)
		result = append(result, pkgbytes.Range{Offset: startIdx, Length: uint64(seg.Size)})
	}

	return result
}

// calculateOffsetFromPhysAddr calculates the offset within an image
// of the physical address (address to a region mapped from
// the SPI chip).
//
// Examples:
//
//	calculateOffsetFromPhysAddr(0xffffffff, 0x1000) == 0xfff
//	calculateOffsetFromPhysAddr(0xffffffc0, 0x1000) == 0xfc0
func calculateOffsetFromPhysAddr(physAddr uint64, imageSize uint64) uint64 {
	const basePhysAddr = 1 << 32 // "4GiB"
	startAddr := basePhysAddr - imageSize
	return physAddr - startAddr
}

func (bpm *Manifest) rehashedBPMH() BPMH {
	bpmh := bpm.BPMH
	pmseOffs, _ := bpm.OffsetOf(6)
	keySigOffs, _ := bpm.PMSE.OffsetOf(1)
	bpmh.KeySignatureOffset = uint16(pmseOffs + keySigOffs)
	return bpmh
}

// Print prints the Manifest
func (bpm Manifest) Print() {
	fmt.Printf("%v", bpm.BPMH.PrettyString(1, true))
	for _, item := range bpm.SE {
		fmt.Printf("%v", item.PrettyString(1, true))
	}
	if bpm.TXTE != nil {
		fmt.Printf("%v\n", bpm.TXTE.PrettyString(1, true))
	} else {
		fmt.Printf("  --TXTE--\n\t not set!(optional)\n")
	}

	if bpm.PCDE != nil {
		fmt.Printf("%v\n", bpm.PCDE.PrettyString(1, true))
	} else {
		fmt.Println("  --PCDE-- \n\tnot set!(optional)")
	}

	if bpm.PME != nil {
		fmt.Printf("%v\n", bpm.PME.PrettyString(1, true))
	} else {
		fmt.Println("  --PME--\n\tnot set!(optional)")
	}

	if len(bpm.PMSE.Signature.Data) < 1 {
		fmt.Printf("%v\n", bpm.PMSE.PrettyString(1, true, pretty.OptionOmitKeySignature(true)))
		fmt.Printf("  --PMSE--\n\tBoot Policy Manifest not signed!\n\n")
	} else {
		fmt.Printf("%v\n", bpm.PMSE.PrettyString(1, true, pretty.OptionOmitKeySignature(false)))
	}
}
