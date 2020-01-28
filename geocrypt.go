// Copyright ©2019 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package geocrypt implements a geographic cryptographic hash.
package geocrypt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"

	"golang.org/x/crypto/bcrypt"
)

const (
	// MinPrecision is the minimum allowable precision
	// that may be passed to Hash and Error.
	MinPrecision = 1

	// MaxPrecision is the maximum allowable precision
	// that may be passed to Hash and Error.
	MaxPrecision = 9

	// DefaultPrecision corresponds to approximately one
	// diagonal metre at the equator.
	DefaultPrecision = 7
)

// The error returned from Compare when a location and hash do not match.
var ErrMismatchedHashAndLocation = errors.New("geocrypt: hashedLocation is not the hash of the given location")

// The error returned from Hash and Geohash when the precision is out of the valid range.
var ErrInvalidPrecision = errors.New("geocrypt: location precision out of range")

// The error returned from Hash or Compare when note text is longer than 64 bytes.
var ErrTextTooLong = errors.New("geocrypt: note text is too long")

// Hash returns the geocrypt hash set of the location at the given
// latitude and longitude and note text with the given precisions.
// The note text is appended to the geohash of the location before
// hashing. If no precision is given, DefaultPrecision is used. When
// more than one precision is given, the hashes are concatenated in
// order of descending precision.
func Hash(lat, long float64, text string, precs ...int) ([]byte, error) {
	if len(text) > 64 {
		return nil, ErrTextTooLong
	}
	for i, p := range precs {
		if p < MinPrecision || MaxPrecision < p {
			return nil, fmt.Errorf("%w: position %d: %d", ErrInvalidPrecision, i, p)
		}
	}
	switch len(precs) {
	case 0:
		precs = []int{DefaultPrecision}
	case 1:
		// Do nothing.
	default:
		precs = append([]int(nil), precs...)
		sort.Sort(sort.Reverse(sort.IntSlice(precs)))
		i, j := 0, 1
		for j < len(precs) {
			if precs[i] > precs[j] {
				i++
				if i != j {
					precs[i], precs[j] = precs[j], precs[i]
				}
			}
			j++
		}
		precs = precs[:i+1]
	}

	var buf bytes.Buffer
	for i, p := range precs {
		if i != 0 {
			buf.WriteByte(':')
		}
		bits := Bits(p)
		cost := 66 - bits
		var b [72]byte
		binary.BigEndian.PutUint64(b[:8], geohash(lat, long)&(^uint64(0)<<(64-bits)))
		h, err := bcrypt.GenerateFromPassword(append(b[:8], text...), int(cost))
		if err != nil {
			return nil, err
		}
		buf.Write(h)
	}
	return buf.Bytes(), nil
}

// Compare compares the geocrypt hashed location with the location
// at latitude and longitude and note text. The note text is appended
// the the geohash of the location before comparing to the hashed
// location. It returns the highest number of geohash precision bits
// in the hash set on success or an error on failure.
func Compare(hashedLocation []byte, lat, long float64, text string) (bits int, err error) {
	for _, h := range bytes.Split(hashedLocation, []byte{':'}) {
		bits, err = compare(h, lat, long, text)
		if err == nil {
			return bits, nil
		}
	}
	return 0, ErrMismatchedHashAndLocation
}

func compare(hashedLocation []byte, lat, long float64, text string) (bits int, err error) {
	if len(text) > 64 {
		return 0, ErrTextTooLong
	}
	cost, err := bcrypt.Cost(hashedLocation)
	if err != nil {
		return 0, err
	}
	bits = 66 - cost
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], geohash(lat, long)&(^uint64(0)<<(64-bits)))
	err = bcrypt.CompareHashAndPassword(hashedLocation, append(b[:], text...))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		bits = 0
		err = ErrMismatchedHashAndLocation
	}
	return bits, err
}

// Bits returns the geohash bit precision corresponding to the given
// geocrypt precision.
func Bits(prec int) int {
	return 4 * (prec + 6)
}

// Prec returns the geocrypt precision corresponding to the given
// geohash bit precision.
func Prec(bits int) int {
	return bits/4 - 6
}

// Geohash returns the geohash for the given latitude and longitude with
// the given bit precision. The value of bits must not be less than five
// or greater than 60.
func Geohash(lat, long float64, bits int) ([]byte, error) {
	if bits < 5 || 60 < bits {
		return nil, ErrInvalidPrecision
	}
	return base32(geohash(lat, long) >> 4)[:bits/5], nil
}

func geohash(lat, long float64) uint64 {
	return zip(integer(lat, long))
}

func zip(x, y uint32) uint64 {
	return spread(x) | (spread(y) << 1)
}

// http://graphics.stanford.edu/~seander/bithacks.html#InterleaveBMN
func spread(x uint32) uint64 {
	_x := uint64(x)
	_x = (_x | (_x << 16)) & 0x0000ffff0000ffff
	_x = (_x | (_x << 8)) & 0x00ff00ff00ff00ff
	_x = (_x | (_x << 4)) & 0x0f0f0f0f0f0f0f0f
	_x = (_x | (_x << 2)) & 0x3333333333333333
	_x = (_x | (_x << 1)) & 0x5555555555555555
	return _x
}

func integer(lat, long float64) (lat32, long32 uint32) {
	return uint32(math.Ldexp((lat+90)/180, 32)), uint32(math.Ldexp((long+180)/360, 32))
}

// Location returns the latitude and longitude for a geohash, along
// the bit precision of the geohash.
func Location(geohash []byte) (lat, long float64, bits int, err error) {
	bits = 5 * len(geohash)
	gh, err := decodeBase32(geohash)
	if err != nil {
		return 0, 0, 0, err
	}
	lat, long = float(unzip(gh << (64 - bits)))
	return lat, long, bits, nil
}

func float(lat32, long32 uint32) (lat, long float64) {
	return math.Ldexp(float64(lat32)*180, -32) - 90, math.Ldexp(float64(long32)*360, -32) - 180
}

func unzip(v uint64) (x, y uint32) {
	return squash(v), squash(v >> 1)
}

// http://graphics.stanford.edu/~seander/bithacks.html#InterleaveBMN inverted.
func squash(x uint64) uint32 {
	x &= 0x5555555555555555
	x = (x | (x >> 1)) & 0x3333333333333333
	x = (x | (x >> 2)) & 0x0f0f0f0f0f0f0f0f
	x = (x | (x >> 4)) & 0x00ff00ff00ff00ff
	x = (x | (x >> 8)) & 0x0000ffff0000ffff
	return uint32(x | (x >> 16))
}

// Error returns the latitude and longitude error for the given bit precision.
// It will return NaN when bits is less than one or greater than 60.
func Error(bits int) (lat, long float64) {
	if bits < 1 || 60 < bits {
		return math.NaN(), math.NaN()
	}
	latPrec := bits / 2
	longPrec := bits - latPrec
	return math.Ldexp(180, -latPrec), math.Ldexp(360, -longPrec)
}

func base32(x uint64) []byte {
	var b [12]byte // Bit length is highest multiple of 5 and 4 within 64.
	for i := 11; i >= 0; i-- {
		b[i] = "0123456789bcdefghjkmnpqrstuvwxyz"[x&0x1f]
		x >>= 5
	}
	return b[:]
}

func decodeBase32(bytes []byte) (uint64, error) {
	var x uint64
	for _, b := range bytes {
		if b < '0' || 'z' < b {
			return 0, errors.New("geocrypt: invalid base32")
		}
		v := encoding[b]
		if v == 0xff {
			return 0, errors.New("geocrypt: invalid base32")
		}
		x = (x << 5) | uint64(v)
	}
	return x, nil
}

var encoding = [255]byte{
	'0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7,
	'8': 8, '9': 9, 'b': 10, 'c': 11, 'd': 12, 'e': 13, 'f': 14, 'g': 15,
	'h': 16, 'j': 17, 'k': 18, 'm': 19, 'n': 20, 'p': 21, 'q': 22, 'r': 23,
	's': 24, 't': 25, 'u': 26, 'v': 27, 'w': 28, 'x': 29, 'y': 30, 'z': 31,

	'a': 0xff, 'i': 0xff, 'l': 0xff, 'o': 0xff,
}
