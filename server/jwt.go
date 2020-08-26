// Copyright 2018-2019 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"io/ioutil"
	"regexp"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
)

var nscDecoratedRe = regexp.MustCompile(`\s*(?:(?:[-]{3,}[^\n]*[-]{3,}\n)(.+)(?:\n\s*[-]{3,}[^\n]*[-]{3,}[\n]*))`)

// All JWTs once encoded start with this
const jwtPrefix = "eyJ"

// ReadOperatorJWT will read a jwt file for an operator claim. This can be a decorated file.
func ReadOperatorJWT(jwtfile string) (*jwt.OperatorClaims, error) {
	contents, err := ioutil.ReadFile(jwtfile)
	if err != nil {
		// Check to see if the JWT has been inlined.
		if !strings.HasPrefix(jwtfile, jwtPrefix) {
			return nil, err
		}
		// We may have an inline jwt here.
		contents = []byte(jwtfile)
	}
	defer wipeSlice(contents)

	var claim string
	items := nscDecoratedRe.FindAllSubmatch(contents, -1)
	if len(items) == 0 {
		claim = string(contents)
	} else {
		// First result should be the JWT.
		// We copy here so that if the file contained a seed file too we wipe appropriately.
		raw := items[0][1]
		tmp := make([]byte, len(raw))
		copy(tmp, raw)
		claim = string(tmp)
	}
	opc, err := jwt.DecodeOperatorClaims(claim)
	if err != nil {
		return nil, err
	}
	return opc, nil
}

// Just wipe slice with 'x', for clearing contents of nkey seed file.
func wipeSlice(buf []byte) {
	for i := range buf {
		buf[i] = 'x'
	}
}

func validateTimes(claims *jwt.UserClaims) (bool, time.Duration) {
	if claims == nil {
		return false, time.Duration(0)
	} else if len(claims.Times) == 0 {
		return true, time.Duration(0)
	}
	now := time.Now()
	for _, timeRange := range claims.Times {
		y, m, d := now.Date()
		m = m - 1
		d = d - 1
		start, err := time.ParseInLocation("15:04:05", timeRange.Start, now.Location())
		if err != nil {
			return false, time.Duration(0) // parsing not expected to fail at this point
		}
		end, err := time.ParseInLocation("15:04:05", timeRange.End, now.Location())
		if err != nil {
			return false, time.Duration(0) // parsing not expected to fail at this point
		}
		if start.After(end) {
			start = start.AddDate(y, int(m), d)
			d++ // the intent is to be the next day
		} else {
			start = start.AddDate(y, int(m), d)
		}
		if start.Before(now) {
			end = end.AddDate(y, int(m), d)
			if end.After(now) {
				return true, end.Sub(now)
			}
		}
	}
	return false, time.Duration(0)
}
