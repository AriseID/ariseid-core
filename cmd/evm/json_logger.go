// Copyright 2017 The AriseID Authors
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

package main

import (
	"encoding/json"
	"io"
	"time"

	"github.com/ariseid/ariseid-core/common"
	"github.com/ariseid/ariseid-core/common/math"
	"github.com/ariseid/ariseid-core/core/vm"
)

type JSONLogger struct {
	encoder *json.Encoder
	cfg     *vm.LogConfig
}

func NewJSONLogger(cfg *vm.LogConfig, writer io.Writer) *JSONLogger {
	return &JSONLogger{json.NewEncoder(writer), cfg}
}

// CaptureState outputs state information on the logger.
func (l *JSONLogger) CaptureState(env *vm.EVM, pc uint64, op vm.OpCode, life, cost uint64, memory *vm.Memory, stack *vm.Stack, contract *vm.Contract, depth int, err error) error {
	log := vm.StructLog{
		Pc:         pc,
		Op:         op,
		Life:        life,
		LifeCost:    cost,
		MemorySize: memory.Len(),
		Storage:    nil,
		Depth:      depth,
		Err:        err,
	}
	if !l.cfg.DisableMemory {
		log.Memory = memory.Data()
	}
	if !l.cfg.DisableStack {
		log.Stack = stack.Data()
	}
	return l.encoder.Encode(log)
}

// CaptureEnd is triggered at end of execution.
func (l *JSONLogger) CaptureEnd(output []byte, lifeUsed uint64, t time.Duration, err error) error {
	type endLog struct {
		Output  string              `json:"output"`
		LifeUsed math.HexOrDecimal64 `json:"lifeUsed"`
		Time    time.Duration       `json:"time"`
		Err     string              `json:"error,omitempty"`
	}
	if err != nil {
		return l.encoder.Encode(endLog{common.Bytes2Hex(output), math.HexOrDecimal64(lifeUsed), t, err.Error()})
	}
	return l.encoder.Encode(endLog{common.Bytes2Hex(output), math.HexOrDecimal64(lifeUsed), t, ""})
}
