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
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/http"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"
)

func TestSyncCommitteeContribution(t *testing.T) {
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

	tests := []struct {
		name              string
		slot              int64 // -1 for current
		subcommitteeIndex uint64
	}{
		{
			name:              "Current",
			slot:              -1,
			subcommitteeIndex: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var slot phase0.Slot
			if test.slot == -1 {
				slot = phase0.Slot(uint64(time.Since(genesis.GenesisTime).Seconds()) / uint64(slotDuration.Seconds()))
			} else {
				slot = phase0.Slot(test.slot)
			}
			root, err := service.BeaconBlockRoot(ctx, "head")
			require.NoError(t, err)
			require.NotNil(t, root)
			contribution, err := service.SyncCommitteeContribution(context.Background(), slot, test.subcommitteeIndex, *root)
			require.NoError(t, err)
			require.NotNil(t, contribution)
			fmt.Printf("%v\n", contribution)
		})
	}
}
