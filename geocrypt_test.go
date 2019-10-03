// Copyright ©2019 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package geocrypt

import (
	"math"
	"testing"
	"testing/quick"
	"time"
)

var locationTests = []struct {
	lat, long float64
}{
	{lat: -36.7522214, long: 141.8259674},
	{lat: 41.9038163, long: 12.4476838},
}

func TestHashCompare(t *testing.T) {
	precs := []int{9, 8, 7, 6, 5}
	if testing.Short() {
		precs = precs[:3]
	}
	for _, test := range locationTests {
		for _, prec := range precs {
			s := time.Now()
			h, err := Hash(test.lat, test.long, prec)
			if err != nil {
				t.Errorf("unexpected hash error: %v", err)
			}
			hashTime := time.Since(s)
			s = time.Now()
			err = Compare(h, test.lat, test.long)
			if err != nil {
				t.Errorf("unexpected hash comparison error: %v", err)
			}
			compareTime := time.Since(s)
			geohash, err := Geohash(test.lat, test.long, Bits(prec))
			if err != nil {
				t.Errorf("unexpected geohash error: %v", err)
			}
			latErr, longErr := Error(Bits(prec))
			t.Logf("diag distance for %s prec %d: %.2fm hash in %v compare in %v", geohash, prec,
				haversine(test.lat-latErr, test.long-longErr, test.lat+latErr, test.long+longErr),
				hashTime, compareTime,
			)
		}
	}
}

func haversine(lat1, long1, lat2, long2 float64) float64 {
	const r = 6371e3 // m
	sdLat := math.Sin(radians(lat2-lat1) / 2)
	sdLong := math.Sin(radians(long2-long1) / 2)
	a := sdLat*sdLat + math.Cos(radians(lat1))*math.Cos(radians(lat2))*sdLong*sdLong
	d := 2 * r * math.Asin(math.Sqrt(a))
	return d // m
}

func radians(d float64) float64 {
	return d * math.Pi / 180
}

func TestBase32(t *testing.T) {
	quick.Check(func(x uint64) bool {
		// This truncates to 60 bits because of base32's
		// 12 byte buffer. So we don't need to discard
		// overflows.
		y, err := decodeBase32(base32(x))
		if err != nil {
			t.Error(err)
			return false
		}
		return x == y
	}, nil)
}

func TestGeohash(t *testing.T) {
	quick.Check(func(lat, long float64, bits int) bool {
		if math.IsNaN(lat) || math.IsNaN(long) {
			return true
		}
		lat = math.Mod(lat, 90)
		long = math.Mod(long, 180)
		if bits < 0 {
			bits = -bits
		}
		bits = bits%56 + 5
		geohash, err := Geohash(lat, long, bits)
		if err != nil {
			t.Errorf("bits=%d: %v", bits, err)
			return false
		}
		_lat, _long, _bits, err := Location(geohash)
		if err != nil {
			t.Error(err)
			return false
		}
		if bits != _bits {
			return false
		}
		latErr, longErr := Error(bits)
		ok := true
		if _lat < lat-latErr || lat+latErr < _lat {
			t.Errorf("latitude out of error bound %s: lat=%f(±%f) long=%f(±%f) got=%f",
				geohash, lat, latErr, long, longErr, _lat)
			ok = false
		}
		if _long < long-longErr || long+longErr < _long {
			t.Errorf("longitude out of error bound %s: lat=%f(±%f) long=%f(±%f) got=%f",
				geohash, lat, latErr, long, longErr, _long)
			ok = false
		}
		return ok
	}, nil)
}

func TestBitsPrec(t *testing.T) {
	for prec := MinPrecision; prec <= MaxPrecision; prec++ {
		if Prec(Bits(prec)) != prec {
			t.Errorf("unexpected result: Prec(Bits(%d)) != %d", Prec(Bits(prec)), prec)
		}
	}
}
