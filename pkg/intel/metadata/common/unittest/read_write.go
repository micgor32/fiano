// Copyright 2017-2026 the LinuxBoot Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package unittest

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	"github.com/linuxboot/fiano/pkg/intel/metadata/common/pretty"
	"github.com/stretchr/testify/require"
)

func sizeList(m cbnt.Manifest) map[int]uint64 {
	var ret map[int]uint64
	ret = make(map[int]uint64)

	for i, f := range m.Layout() {
		ret[i] = f.Size()
	}

	return ret
}

func ManifestReadWrite(t *testing.T, m cbnt.Manifest, testDataFilePath string) {
	testData, err := os.ReadFile(testDataFilePath)
	require.NoError(t, err)

	nR, err := m.ReadFrom(bytes.NewReader(append(testData, []byte(`extra bytes`)...)))
	require.NoError(t, err)
	require.Equal(t, int64(len(testData)), nR)

	// We have to read the values AFTER the read, otherwise all the fields of dynamic
	// type will be incorrect (obviously).
	list := sizeList(m)

	// Sizes
	for i := 0; i < len(m.Layout()); i++ {
		s, err := m.SizeOf(i)
		require.NoError(t, err)
		require.Equal(t, list[i], s)
	}

	// Offsets
	s, err := m.OffsetOf(0)
	require.NoError(t, err)
	require.Equal(t, uint64(0), s)

	prev := list[0]
	for i := 1; i < len(m.Layout()); i++ {
		s, err := m.OffsetOf(i)
		require.NoError(t, err)
		require.Equal(t, prev, s)
		prev += list[i]
	}

	// Getters
	l := m.Layout()
	field0 := l[0]
	val := field0.Value

	// So we don't know here what exact type we are testing, but we know it should implement getter and setter.
	// Thus we can make sneaky type assertion to an interface that only has these methids, and let the test fail
	// if the actual type that we are testing contains this methods.
	type structInfoAccessor interface {
		GetStructInfo() cbnt.StructInfo
		SetStructInfo(cbnt.StructInfo)
		Print()
	}

	accessor, ok := m.(structInfoAccessor)
	require.True(t, ok, "Manifest must implement GetStructInfo() and SetStructInfo()")

	originalInfo := accessor.GetStructInfo()
	require.Equal(t, val(), originalInfo, "Getter should return the value from Layout")

	accessor.SetStructInfo(val().(cbnt.StructInfo))
	require.Equal(t, originalInfo, accessor.GetStructInfo(), "Getter should match the value just set")

	// Validate
	err = m.Validate()
	require.NoError(t, err)

	require.Equal(t, nR, int64(m.TotalSize()))

	// Print and PrettyString on WriteTo
	prettyString := m.PrettyString(0, true)
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err, "Failed to create pipe for stdout")
	os.Stdout = w

	accessor.Print()

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err, "Failed to read from pipe")
	actualOutput := buf.String()

	// This really depends on what testDataFilePath was used, but since this is supposed to be generic
	// as possible, let's cover both
	expectedUnsigned := fmt.Sprintf("%v\n  --KeyAndSignature--\n\tKey Manifest not signed!\n\n",
		m.PrettyString(1, true, pretty.OptionOmitKeySignature(true)))

	expectedSigned := fmt.Sprintf("%v\n",
		m.PrettyString(1, true, pretty.OptionOmitKeySignature(false)))

	require.True(t, actualOutput == expectedSigned || actualOutput == expectedUnsigned,
		"Print() output did not match either the signed or unsigned PrettyString format")

	var out bytes.Buffer
	nW, err := m.WriteTo(&out)
	require.NoError(t, err)

	newPrettyString := m.PrettyString(0, true)
	require.Equal(t, prettyString, newPrettyString, newPrettyString)
	require.Equal(t, string(testData), out.String())
	require.Equal(t, nW, nR)
	require.Equal(t, nW, int64(out.Len()))
}
