// Copyright 2017-2021 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate manifestcodegen

package cbnt

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
	"github.com/tjfoc/gmsm/sm2"
)

// TODO: same here

// InBits returns the size in bits.
func (ks BitSize) InBits() uint16 {
	return uint16(ks)
}

// InBytes returns the size in bytes.
func (ks BitSize) InBytes() uint16 {
	return uint16(ks >> 3)
}

// SetInBits sets the size in bits.
func (ks *BitSize) SetInBits(amountOfBits uint16) {
	*ks = BitSize(amountOfBits)
}

// SetInBytes sets the size in bytes.
func (ks *BitSize) SetInBytes(amountOfBytes uint16) {
	*ks = BitSize(amountOfBytes << 3)
}

// keyDataSize returns the expected length of Data for specified
// KeyAlg and KeySize.
func (k Key) keyDataSize() int64 {
	switch k.KeyAlg {
	case AlgRSA:
		return int64(k.KeySize.InBytes()) + 4
	case AlgECC, AlgSM2:
		return int64(k.KeySize.InBytes()) * 2
	}
	return -1
}

// PubKey parses Data into crypto.PublicKey.
func (k Key) PubKey() (crypto.PublicKey, error) {
	expectedSize := int(k.keyDataSize())
	if expectedSize < 0 {
		return nil, fmt.Errorf("unexpected algorithm: %s", k.KeyAlg)
	}
	if len(k.Data) != expectedSize {
		return nil, fmt.Errorf("unexpected size: expected:%d, received %d", expectedSize, len(k.Data))
	}

	switch k.KeyAlg {
	case AlgRSA:
		result := &rsa.PublicKey{
			N: new(big.Int).SetBytes(reverseBytes(k.Data[4:])),
			E: int(BinaryOrder.Uint32(k.Data)),
		}
		return result, nil
	case AlgECC:
		keySize := k.KeySize.InBytes()
		x := new(big.Int).SetBytes(reverseBytes(k.Data[:keySize]))
		y := new(big.Int).SetBytes(reverseBytes(k.Data[keySize:]))
		return ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	case AlgSM2:
		keySize := k.KeySize.InBytes()
		x := new(big.Int).SetBytes(reverseBytes(k.Data[:keySize]))
		y := new(big.Int).SetBytes(reverseBytes(k.Data[keySize:]))
		return sm2.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	}

	return nil, fmt.Errorf("unexpected TPM algorithm: %s", k.KeyAlg)
}

func reverseBytes(b []byte) []byte {
	r := make([]byte, len(b))
	for idx := range b {
		r[idx] = b[len(b)-idx-1]
	}
	return r
}

// SetPubKey sets Data the value corresponding to passed `key`.
func (k *Key) SetPubKey(key crypto.PublicKey) error {
	k.Version = 0x10

	switch key := key.(type) {
	case *rsa.PublicKey:
		k.KeyAlg = AlgRSA
		n := key.N.Bytes()
		k.KeySize.SetInBytes(uint16(len(n)))
		k.Data = make([]byte, 4+len(n))
		BinaryOrder.PutUint32(k.Data, uint32(key.E))
		copy(k.Data[4:], reverseBytes(n))
		return nil

	case *ecdsa.PublicKey:
		var x, y *big.Int
		k.KeyAlg = AlgECC
		x, y = key.X, key.Y
		if x == nil || y == nil {
			return fmt.Errorf("the pubkey '%#+v' is invalid: x == nil || y == nil", key)
		}
		k.KeySize.SetInBits(256)
		xB, yB := x.Bytes(), y.Bytes()
		if len(xB) != int(k.KeySize.InBytes()) || len(yB) != int(k.KeySize.InBytes()) {
			return fmt.Errorf("the pubkey '%#+v' is invalid: len(x)<%d> != %d || len(y)<%d> == %d",
				key, len(xB), int(k.KeySize.InBytes()), len(yB), int(k.KeySize.InBytes()))
		}
		k.Data = make([]byte, 2*k.KeySize.InBytes())
		copy(k.Data[:], reverseBytes(xB))
		copy(k.Data[len(xB):], reverseBytes(yB))
		return nil

	case *sm2.PublicKey:
		var x, y *big.Int
		k.KeyAlg = AlgSM2
		x, y = key.X, key.Y
		if x == nil || y == nil {
			return fmt.Errorf("the pubkey '%#+v' is invalid: x == nil || y == nil", key)
		}
		k.KeySize.SetInBits(256)
		xB, yB := x.Bytes(), y.Bytes()
		if len(xB) != int(k.KeySize.InBytes()) || len(yB) != int(k.KeySize.InBytes()) {
			return fmt.Errorf("the pubkey '%#+v' is invalid: len(x)<%d> != %d || len(y)<%d> == %d",
				key, len(xB), int(k.KeySize.InBytes()), len(yB), int(k.KeySize.InBytes()))
		}
		k.Data = make([]byte, 2*k.KeySize.InBytes())
		copy(k.Data[:], reverseBytes(xB))
		copy(k.Data[len(xB):], reverseBytes(yB))
		return nil
	}

	return fmt.Errorf("unexpected key type: %T", key)
}

// PrintBPMPubKey prints the BPM public signing key hash to fuse into the Intel ME
func (k *Key) PrintBPMPubKey(bpmAlg Algorithm) error {
	buf := new(bytes.Buffer)
	if len(k.Data) > 1 {
		hash, err := bpmAlg.Hash()
		if err != nil {
			return err
		}
		if k.KeyAlg == AlgRSA {
			if err := binary.Write(buf, binary.LittleEndian, k.Data[4:]); err != nil {
				return err
			}
			if _, err := hash.Write(buf.Bytes()); err != nil {
				return fmt.Errorf("unable to hash: %w", err)
			}
			fmt.Printf("   Boot Policy Manifest Pubkey Hash: 0x%x\n", hash.Sum(nil))
		} else if k.KeyAlg == AlgSM2 || k.KeyAlg == AlgECC {
			if err := binary.Write(buf, binary.LittleEndian, k.Data); err != nil {
				return err
			}
			if _, err := hash.Write(buf.Bytes()); err != nil {
				return fmt.Errorf("unable to hash: %w", err)
			}
			fmt.Printf("   Boot Policy Manifest Pubkey Hash: 0x%x\n", hash.Sum(nil))
		} else {
			fmt.Printf("   Boot Policy Manifest Pubkey Hash: Unknown Algorithm\n")
		}
	} else {
		fmt.Printf("   Boot Policy Pubkey Hash: No km public key set in KM\n")
	}

	return nil
}

// PrintKMPubKey prints the KM public signing key hash to fuse into the Intel ME
func (k *Key) PrintKMPubKey(kmAlg Algorithm) error {
	buf := new(bytes.Buffer)
	if len(k.Data) > 1 {
		if k.KeyAlg == AlgRSA {
			if err := binary.Write(buf, binary.LittleEndian, k.Data[4:]); err != nil {
				return err
			}
			if err := binary.Write(buf, binary.LittleEndian, k.Data[:4]); err != nil {
				return err
			}
			if kmAlg != AlgSHA256 && kmAlg != AlgSHA384 {
				return fmt.Errorf("KM public key hash algorithm must be SHA256 or SHA384")
			}
			hash, err := kmAlg.Hash()
			if err != nil {
				return err
			}
			if _, err := hash.Write(buf.Bytes()); err != nil {
				return fmt.Errorf("unable to hash: %w", err)
			}
			fmt.Printf("   Key Manifest Pubkey Hash: 0x%x\n", hash.Sum(nil))
			// On SKL and KBL the exponent is not included in the KM hash
			buf.Truncate(len(k.Data[4:]))
			hash.Reset()
			if _, err := hash.Write(buf.Bytes()); err != nil {
				return fmt.Errorf("unable to hash: %w", err)
			}
			fmt.Printf("   Key Manifest Pubkey Hash (Skylake and Kabylake only): 0x%x\n", hash.Sum(nil))
		} else {
			fmt.Printf("   Key Manifest Pubkey Hash: Unsupported Algorithm\n")
		}
	} else {
		fmt.Printf("   Key Manifest Pubkey Hash: No km public key set in KM\n")
	}

	return nil
}

// NewKey returns a new instance of Key with
// all default values set.
func NewKey() *Key {
	s := &Key{}
	// Set through tag "required":
	s.Version = 0x10
	s.Rehash()
	return s
}

// Validate (recursively) checks the structure if there are any unexpected
// values. It returns an error if so.
func (s *Key) Validate() error {
	// See tag "require"
	if s.Version != 0x10 {
		return fmt.Errorf("field 'Version' expects value '0x10', but has %v", s.Version)
	}

	return nil
}

// ReadFrom reads the Key from 'r' in format defined in the document #575623.
func (s *Key) ReadFrom(r io.Reader) (int64, error) {
	totalN := int64(0)

	// KeyAlg (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Read(r, binary.LittleEndian, &s.KeyAlg)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'KeyAlg': %w", err)
		}
		totalN += int64(n)
	}

	// Version (ManifestFieldType: endValue)
	{
		n, err := 1, binary.Read(r, binary.LittleEndian, &s.Version)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'Version': %w", err)
		}
		totalN += int64(n)
	}

	// KeySize (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Read(r, binary.LittleEndian, &s.KeySize)
		if err != nil {
			return totalN, fmt.Errorf("unable to read field 'KeySize': %w", err)
		}
		totalN += int64(n)
	}

	// Data (ManifestFieldType: arrayDynamic)
	{
		size := uint16(s.keyDataSize())
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
func (s *Key) RehashRecursive() {
	s.Rehash()
}

// Rehash sets values which are calculated automatically depending on the rest
// data. It is usually about the total size field of an element.
func (s *Key) Rehash() {
}

// WriteTo writes the Key into 'w' in format defined in
// the document #575623.
func (s *Key) WriteTo(w io.Writer) (int64, error) {
	totalN := int64(0)
	s.Rehash()

	// KeyAlg (ManifestFieldType: endValue)
	{
		n, err := 2, binary.Write(w, binary.LittleEndian, &s.KeyAlg)
		if err != nil {
			return totalN, fmt.Errorf("unable to write field 'KeyAlg': %w", err)
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

// KeyAlgSize returns the size in bytes of the value of field KeyAlg
func (s *Key) KeyAlgTotalSize() uint64 {
	return 2
}

// VersionSize returns the size in bytes of the value of field Version
func (s *Key) VersionTotalSize() uint64 {
	return 1
}

// KeySizeSize returns the size in bytes of the value of field KeySize
func (s *Key) KeySizeTotalSize() uint64 {
	return 2
}

// DataSize returns the size in bytes of the value of field Data
func (s *Key) DataTotalSize() uint64 {
	return uint64(len(s.Data))
}

// KeyAlgOffset returns the offset in bytes of field KeyAlg
func (s *Key) KeyAlgOffset() uint64 {
	return 0
}

// VersionOffset returns the offset in bytes of field Version
func (s *Key) VersionOffset() uint64 {
	return s.KeyAlgOffset() + s.KeyAlgTotalSize()
}

// KeySizeOffset returns the offset in bytes of field KeySize
func (s *Key) KeySizeOffset() uint64 {
	return s.VersionOffset() + s.VersionTotalSize()
}

// DataOffset returns the offset in bytes of field Data
func (s *Key) DataOffset() uint64 {
	return s.KeySizeOffset() + s.KeySizeTotalSize()
}

// Size returns the total size of the Key.
func (s *Key) TotalSize() uint64 {
	if s == nil {
		return 0
	}

	var size uint64
	size += s.KeyAlgTotalSize()
	size += s.VersionTotalSize()
	size += s.KeySizeTotalSize()
	size += s.DataTotalSize()
	return size
}

// PrettyString returns the content of the structure in an easy-to-read format.
func (s *Key) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "Key", s))
	}
	if s == nil {
		return strings.Join(lines, "\n")
	}
	// ManifestFieldType is endValue
	lines = append(lines, pretty.SubValue(depth+1, "Key Alg", "", &s.KeyAlg, opts...)...)
	// ManifestFieldType is endValue
	lines = append(lines, pretty.SubValue(depth+1, "Version", "", &s.Version, opts...)...)
	// ManifestFieldType is endValue
	lines = append(lines, pretty.SubValue(depth+1, "Key Size", "", &s.KeySize, opts...)...)
	// ManifestFieldType is arrayDynamic
	lines = append(lines, pretty.SubValue(depth+1, "Data", "", &s.Data, opts...)...)
	if depth < 2 {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

// PrettyString returns the bits of the flags in an easy-to-read format.
func (v BitSize) PrettyString(depth uint, withHeader bool, opts ...pretty.Option) string {
	var lines []string
	if withHeader {
		lines = append(lines, pretty.Header(depth, "Bit Size", v))
	}
	lines = append(lines, pretty.SubValue(depth+1, "In Bits", "", v.InBits(), opts...)...)
	lines = append(lines, pretty.SubValue(depth+1, "In Bytes", "", v.InBytes(), opts...)...)
	return strings.Join(lines, "\n")
}

// TotalSize returns the total size measured through binary.Size.
func (v BitSize) TotalSize() uint64 {
	return uint64(binary.Size(v))
}

// WriteTo writes the BitSize into 'w' in binary format.
func (v BitSize) WriteTo(w io.Writer) (int64, error) {
	return int64(v.TotalSize()), binary.Write(w, binary.LittleEndian, v)
}

// ReadFrom reads the BitSize from 'r' in binary format.
func (v BitSize) ReadFrom(r io.Reader) (int64, error) {
	return int64(v.TotalSize()), binary.Read(r, binary.LittleEndian, v)
}
