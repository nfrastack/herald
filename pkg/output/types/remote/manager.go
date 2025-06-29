// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package remote

import (
	"herald/pkg/log"
	"herald/pkg/output"
)

func init() {
	log.Info("[output/types/remote/manager] Registering remote output provider via RegisterFormat")
	output.RegisterFormat("remote", NewRemoteFormat)
}
