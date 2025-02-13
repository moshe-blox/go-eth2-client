// Copyright © 2021 Attestant Limited.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package http_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/http"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"
)

func TestSyncCommitteeDuties(t *testing.T) {
	ctx := context.Background()

	service, err := http.New(ctx,
		http.WithTimeout(timeout),
		http.WithAddress(os.Getenv("HTTP_ADDRESS")),
	)
	require.NoError(t, err)

	// Needed to fetch current epoch.
	genesis, err := service.Genesis(context.Background())
	require.NoError(t, err)
	slotDuration, err := service.SlotDuration(context.Background())
	require.NoError(t, err)
	slotsPerEpoch, err := service.SlotsPerEpoch(context.Background())
	require.NoError(t, err)

	tests := []struct {
		name             string
		epoch            int64 // -1 for current
		validatorIndices []phase0.ValidatorIndex
	}{
		{
			name:             "Current",
			epoch:            -1,
			validatorIndices: []phase0.ValidatorIndex{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var epoch phase0.Epoch
			if test.epoch == -1 {
				epoch = phase0.Epoch(uint64(time.Since(genesis.GenesisTime).Seconds()) / (uint64(slotDuration.Seconds()) * slotsPerEpoch))
			} else {
				epoch = phase0.Epoch(test.epoch)
			}
			duties, err := service.SyncCommitteeDuties(context.Background(), epoch, test.validatorIndices)
			require.NoError(t, err)
			require.NotNil(t, duties)
			require.True(t, len(duties) > 0)
		})
	}
}
