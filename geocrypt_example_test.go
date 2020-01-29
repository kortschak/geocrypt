// Copyright ©2020 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package geocrypt_test

import (
	"fmt"
	"log"

	"github.com/kortschak/geocrypt"
)

func Example_kryptos() {
	lat := 38.9521808
	lon := -77.1458137
	text := "Kryptos"
	prec := 6

	bits := geocrypt.Bits(prec)
	latErr, lonErr := geocrypt.Error(bits)

	fmt.Printf("prec=%d bits=%d error lat=%.2e lon=%.2e\n", prec, bits, latErr, lonErr)

	h, err := geocrypt.Hash(lat, lon, text, prec)
	if err != nil {
		log.Fatal(err)
	}

	// Compare against reduced accuracy location.
	// First without note text.
	fmt.Println(geocrypt.Compare(h, 38.95218, -77.14581, ""))
	// And then with note text.
	fmt.Println(geocrypt.Compare(h, 38.95218, -77.14581, text))

	// Output:
	//
	// prec=6 bits=48 error lat=1.07e-05 lon=2.15e-05
	// 0 geocrypt: hashedLocation is not the hash of the given location
	// 48 <nil>
}
