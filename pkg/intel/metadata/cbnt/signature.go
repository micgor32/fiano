// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate manifestcodegen

package cbnt

import (
	"crypto"
	"fmt"
	"math/big"

	"encoding/binary"
	"io"

	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
)

// NewSignature returns a new instance of Signature with
// all default values set.
func NewSignature() *Signature {
	s := &Signature{}
	// Set through tag "required":
	s.Version = 0x10
	s.Rehash()
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *Signature) Validate() error {
	// See tag "require"
	if s.Version != 0x10 {
		return fmt.Errorf("field 'Version' expects value '0x10', but has %v", s.Version)
	}

	return nil
}

// ReadFrom reads the Signature from 'r' in format defined in the document #575623.
func (s *Signature) ReadFrom(r io.Reader) (int64, error) {
	totalN, err := s.Common.ReadFrom(r, s)
	if err != nil {
		return 0, err
	}

	return totalN, nil
}

// RehashRecursive calls Rehash (see below) recursively.
func (s *Signature) RehashRecursive() {
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *Signature) Rehash() {
}

// WriteTo writes the Signature into 'w' in format defined in
// the document #575623.
func (s *Signature) WriteTo(w io.Writer) (int64, error) {
	totalN := int64(0)
	s.Rehash()

	// SigScheme (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Write(w, binary.LittleEndian, &s.SigScheme)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'SigScheme': %w", err)
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

	// KeySize (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Write(w, binary.LittleEndian, &s.KeySize)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'KeySize': %w", err)
		}
		totalN += int64(n)
	}

	// HashAlg (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Write(w, binary.LittleEndian, &s.HashAlg)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'HashAlg': %w", err)
		}
		totalN += int64(n)
	}

	// Data (ManifestFieldType: arrayDynamic)
	{
		n, err := len(s.Data), binary.Write(w, binary.LittleEndian, s.Data)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'Data': %w", err)
		}
		totalN += int64(n)
	}

	return totalN, nil
}

func (s *Signature) Layout() []LayoutField {
	return []LayoutField{
		{
			Name:  "Sig Scheme",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.SigScheme },
			Type:  ManifestFieldEndValue,
		},
		{
			Name:  "Version",
			Size:  func() uint64 { return 1 },
			Value: func() any { return &s.Version },
			Type:  ManifestFieldEndValue,
		},
		{
			Name:  "Key Size",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.KeySize },
			Type:  ManifestFieldEndValue,
		},
		{
			Name:  "Hash Alg",
			Size:  func() uint64 { return 2 },
			Value: func() any { return &s.HashAlg },
			Type:  ManifestFieldEndValue,
		},
		{
			Name:  "Data",
			Size:  func() uint64 { return uint64(s.KeySize.InBytes()) },
			Value: func() any { return &s.Data },
			Type:  ManifestFieldArrayDynamicWithSize,
		},
	}
}

// // SigSchemeSize returns the size in bytes of the value of field SigScheme
// func (s *Signature) SigSchemeTotalSize() uint64 {
// 	return 2
// }
//
// // VersionSize returns the size in bytes of the value of field Version
// func (s *Signature) VersionTotalSize() uint64 {
// 	return 1
// }
//
// // KeySizeSize returns the size in bytes of the value of field KeySize
// func (s *Signature) KeySizeTotalSize() uint64 {
// 	return 2
// }
//
// // HashAlgSize returns the size in bytes of the value of field HashAlg
// func (s *Signature) HashAlgTotalSize() uint64 {
// 	return 2
// }
//
// // DataSize returns the size in bytes of the value of field Data
// func (s *Signature) DataTotalSize() uint64 {
// 	return uint64(len(s.Data))
// }
//
// // SigSchemeOffset returns the offset in bytes of field SigScheme
// func (s *Signature) SigSchemeOffset() uint64 {
// 	return 0
// }
//
// // VersionOffset returns the offset in bytes of field Version
// func (s *Signature) VersionOffset() uint64 {
// 	return s.SigSchemeOffset() + s.SigSchemeTotalSize()
// }
//
// // KeySizeOffset returns the offset in bytes of field KeySize
// func (s *Signature) KeySizeOffset() uint64 {
// 	return s.VersionOffset() + s.VersionTotalSize()
// }
//
// // HashAlgOffset returns the offset in bytes of field HashAlg
// func (s *Signature) HashAlgOffset() uint64 {
// 	return s.KeySizeOffset() + s.KeySizeTotalSize()
// }
//
// // DataOffset returns the offset in bytes of field Data
// func (s *Signature) DataOffset() uint64 {
// 	return s.HashAlgOffset() + s.HashAlgTotalSize()
// }
//
// // Size returns the total size of the Signature.
// func (s *Signature) TotalSize() uint64 {
// 	if s == nil {
// 		return 0
// 	}
//
// 	var size uint64
// 	size += s.SigSchemeTotalSize()
// 	size += s.VersionTotalSize()
// 	size += s.KeySizeTotalSize()
// 	size += s.HashAlgTotalSize()
// 	size += s.DataTotalSize()
// 	return size
// }

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *Signature) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	return Common{}.PrettyString(depth, withHeader, s, "Signature", opts...)
}

func (m Signature) dataPrettyValue() any {
	r, _ := m.SignatureData()
	return r
}

// SignatureData parses field Data and returns the signature as one of these types:
// * SignatureRSAPSS
// * SignatureRSAASA
// * SignatureECDSA
// * SignatureSM2
func (m Signature) SignatureData() (SignatureDataInterface, error) {
	switch m.SigScheme {
	case AlgRSAPSS:
		return SignatureRSAPSS(m.Data), nil
	case AlgRSASSA:
		return SignatureRSAASA(m.Data), nil
	case AlgECDSA:
		if len(m.Data) != 64 && len(m.Data) != 96 {
			return nil, fmt.Errorf("invalid length of the signature data: %d (expected 64 or 96)", len(m.Data))
		}
		return SignatureECDSA{
			R: new(big.Int).SetBytes(reverseBytes(m.Data[:len(m.Data)/2])),
			S: new(big.Int).SetBytes(reverseBytes(m.Data[len(m.Data)/2:])),
		}, nil
	case AlgSM2:
		if len(m.Data) != 64 && len(m.Data) != 96 {
			return nil, fmt.Errorf("invalid length of the signature data: %d (expected 64 or 96)", len(m.Data))
		}
		return SignatureSM2{
			R: new(big.Int).SetBytes(reverseBytes(m.Data[:len(m.Data)/2])),
			S: new(big.Int).SetBytes(reverseBytes(m.Data[len(m.Data)/2:])),
		}, nil
	}

	return nil, fmt.Errorf("unexpected signature scheme: %s", m.SigScheme)
}

// SetSignatureByData sets all the fields of the structure Signature by
// accepting one of these types as the input argument `sig`:
// * SignatureRSAPSS
// * SignatureRSAASA
// * SignatureECDSA
// * SignatureSM2
func (m *Signature) SetSignatureByData(sig SignatureDataInterface, hashAlgo Algorithm) error {
	err := m.SetSignatureData(sig)
	if err != nil {
		return err
	}

	switch sig := sig.(type) {
	case SignatureRSAPSS:
		m.SigScheme = AlgRSAPSS
		if hashAlgo.IsNull() {
			m.HashAlg = AlgSHA384
		} else {
			m.HashAlg = hashAlgo
		}
		m.KeySize.SetInBytes(uint16(len(m.Data)))
	case SignatureRSAASA:
		m.SigScheme = AlgRSASSA
		if hashAlgo.IsNull() {
			m.HashAlg = AlgSHA256
		} else {
			m.HashAlg = hashAlgo
		}
		m.KeySize.SetInBytes(uint16(len(m.Data)))
	case SignatureECDSA:
		m.SigScheme = AlgECDSA
		if hashAlgo.IsNull() {
			m.HashAlg = AlgSHA512
		} else {
			m.HashAlg = hashAlgo
		}
		m.KeySize.SetInBits(uint16(sig.R.BitLen()))
	case SignatureSM2:
		m.SigScheme = AlgSM2
		if hashAlgo.IsNull() {
			m.HashAlg = AlgSM3
		} else {
			m.HashAlg = hashAlgo
		}
		m.KeySize.SetInBits(uint16(sig.R.BitLen()))
	default:
		return fmt.Errorf("unexpected signature type: %T", sig)
	}
	return nil
}

// SetSignatureData sets the value of the field Data by accepting one of these
// types as the input argument `sig`:
// * SignatureRSAPSS
// * SignatureRSAASA
// * SignatureECDSA
// * SignatureSM2
func (m *Signature) SetSignatureData(sig SignatureDataInterface) error {
	switch sig := sig.(type) {
	case SignatureRSAPSS:
		m.Data = sig
	case SignatureRSAASA:
		m.Data = sig
	case SignatureECDSA, SignatureSM2:
		var r, s *big.Int
		switch sig := sig.(type) {
		case SignatureECDSA:
			r, s = sig.R, sig.S
		case SignatureSM2:
			r, s = sig.R, sig.S
		default:
			return fmt.Errorf("internal error")
		}
		if r.BitLen() != s.BitLen() {
			return fmt.Errorf("the length of component R (%d) is not equal to the length of component S (%d)", r.BitLen(), s.BitLen())
		}
		if r.BitLen() != 256 && r.BitLen() != 384 {
			return fmt.Errorf("component R (or S) size should be 256 or 384 bites (not %d)", r.BitLen())
		}
		m.Data = make([]byte, r.BitLen()/8+s.BitLen()/8)
		copy(m.Data[:], reverseBytes(r.Bytes()))
		copy(m.Data[r.BitLen()/8:], reverseBytes(s.Bytes()))
	default:
		return fmt.Errorf("unexpected signature type: %T", sig)
	}
	return nil
}

// SetSignature calculates the signature accordingly to arguments signAlgo,
// privKey and signedData; and sets all the fields of the structure Signature.
//
// if signAlgo is zero then it is detected automatically, based on the type
// of the provided private key.
func (m *Signature) SetSignature(signAlgo Algorithm, hashAlgo Algorithm, privKey crypto.Signer, signedData []byte) error {
	m.Version = 0x10
	m.HashAlg = hashAlgo
	signData, err := NewSignatureData(signAlgo, privKey, signedData)
	if err != nil {
		return fmt.Errorf("unable to construct the signature data: %w", err)
	}
	err = m.SetSignatureByData(signData, m.HashAlg)
	if err != nil {
		return fmt.Errorf("unable to set the signature: %w", err)
	}

	return nil
}

// FillSignature sets the signature accordingly to arguments signAlgo,
// pubKey and signedData; and sets all the fields of the structure Signature.
//
// if signAlgo is zero then it is detected automatically, based on the type
// of the provided private key.
func (m *Signature) FillSignature(signAlgo Algorithm, pubKey crypto.PublicKey, signedData []byte, hashAlgo Algorithm) error {
	m.Version = 0x10
	signData, err := NewSignatureByData(signAlgo, pubKey, signedData)
	if err != nil {
		return fmt.Errorf("unable to construct the signature data: %w", err)
	}

	err = m.SetSignatureByData(signData, hashAlgo)
	if err != nil {
		return fmt.Errorf("unable to set the signature: %w", err)
	}

	return nil
}
