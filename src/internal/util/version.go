// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package util

var Version = "development"

func UserAgent() string {
	return "nfrastack/herald/" + Version
}
