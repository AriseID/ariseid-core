// Copyright 2015 The AriseID Authors
// This file is part of the AriseID library.
//
// The AriseID library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The AriseID library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the AriseID library. If not, see <http://www.gnu.org/licenses/>.

// Contains the metrics collected by the fetcher.

package fetcher

import (
	"github.com/ariseid/ariseid-core/metrics"
)

var (
	propAnnounceInMeter   = metrics.NewMeter("aid/fetcher/prop/announces/in")
	propAnnounceOutTimer  = metrics.NewTimer("aid/fetcher/prop/announces/out")
	propAnnounceDropMeter = metrics.NewMeter("aid/fetcher/prop/announces/drop")
	propAnnounceDOSMeter  = metrics.NewMeter("aid/fetcher/prop/announces/dos")

	propBroadcastInMeter   = metrics.NewMeter("aid/fetcher/prop/broadcasts/in")
	propBroadcastOutTimer  = metrics.NewTimer("aid/fetcher/prop/broadcasts/out")
	propBroadcastDropMeter = metrics.NewMeter("aid/fetcher/prop/broadcasts/drop")
	propBroadcastDOSMeter  = metrics.NewMeter("aid/fetcher/prop/broadcasts/dos")

	headerFetchMeter = metrics.NewMeter("aid/fetcher/fetch/headers")
	bodyFetchMeter   = metrics.NewMeter("aid/fetcher/fetch/bodies")

	headerFilterInMeter  = metrics.NewMeter("aid/fetcher/filter/headers/in")
	headerFilterOutMeter = metrics.NewMeter("aid/fetcher/filter/headers/out")
	bodyFilterInMeter    = metrics.NewMeter("aid/fetcher/filter/bodies/in")
	bodyFilterOutMeter   = metrics.NewMeter("aid/fetcher/filter/bodies/out")
)
