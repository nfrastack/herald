// SPDX-FileCopyrightText: © 2025 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package remote

import (
	"herald/pkg/output/remote"
	"herald/pkg/output/types/common"
)

var NewRemoteFormat = func(profileName string, config map[string]interface{}) (common.OutputFormat, error) {
	return remote.NewRemoteFormat(profileName, config)
}

// (This file is now obsolete. The remote output provider has been moved to pkg/output/remote/remote.go to avoid import cycles and match the fileoutput structure.)
