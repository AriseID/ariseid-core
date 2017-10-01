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

// Contains the metrics collected by the downloader.

package downloader

import (
	"github.com/ariseid/ariseid-core/metrics"
)

var (
	headerInMeter      = metrics.NewMeter("aid/downloader/headers/in")
	headerReqTimer     = metrics.NewTimer("aid/downloader/headers/req")
	headerDropMeter    = metrics.NewMeter("aid/downloader/headers/drop")
	headerTimeoutMeter = metrics.NewMeter("aid/downloader/headers/timeout")

	bodyInMeter      = metrics.NewMeter("aid/downloader/bodies/in")
	bodyReqTimer     = metrics.NewTimer("aid/downloader/bodies/req")
	bodyDropMeter    = metrics.NewMeter("aid/downloader/bodies/drop")
	bodyTimeoutMeter = metrics.NewMeter("aid/downloader/bodies/timeout")

	receiptInMeter      = metrics.NewMeter("aid/downloader/receipts/in")
	receiptReqTimer     = metrics.NewTimer("aid/downloader/receipts/req")
	receiptDropMeter    = metrics.NewMeter("aid/downloader/receipts/drop")
	receiptTimeoutMeter = metrics.NewMeter("aid/downloader/receipts/timeout")

	stateInMeter   = metrics.NewMeter("aid/downloader/states/in")
	stateDropMeter = metrics.NewMeter("aid/downloader/states/drop")
)
