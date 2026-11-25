// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package remote

import (
	"github.com/nfrastack/herald/internal/output"
)

func init() {
	output.RegisterFormat("remote", NewRemoteFormat)
}
