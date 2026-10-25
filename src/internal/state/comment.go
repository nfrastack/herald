// SPDX-FileCopyrightText: © 2026 Nfrastack <code@nfrastack.com>
//
// SPDX-License-Identifier: BSD-3-Clause

package state

import (
	"strings"
	"time"
)

const CommentPrefix = "managed by herald"

func BuildComment(source string, firstSeen, lastModified time.Time) string {
	if firstSeen.IsZero() {
		firstSeen = time.Now().UTC()
	}
	if lastModified.IsZero() {
		lastModified = firstSeen
	}
	firstSeen = firstSeen.UTC()
	lastModified = lastModified.UTC()
	if source == "" {
		source = "herald"
	}
	return CommentPrefix +
		" | source: " + source +
		" | first seen: " + firstSeen.Format(time.RFC3339) +
		" | last modified: " + lastModified.Format(time.RFC3339)
}

func ParseCommentTimestamps(comment string) (source string, firstSeen, lastModified time.Time, ok bool) {
	if !strings.HasPrefix(comment, CommentPrefix) {
		return "", time.Time{}, time.Time{}, false
	}
	for _, part := range strings.Split(comment, "|") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "source:"):
			source = strings.TrimSpace(strings.TrimPrefix(part, "source:"))
		case strings.HasPrefix(part, "first seen:"):
			if ts, err := time.Parse(time.RFC3339, strings.TrimSpace(strings.TrimPrefix(part, "first seen:"))); err == nil {
				firstSeen = ts.UTC()
			}
		case strings.HasPrefix(part, "last modified:"):
			if ts, err := time.Parse(time.RFC3339, strings.TrimSpace(strings.TrimPrefix(part, "last modified:"))); err == nil {
				lastModified = ts.UTC()
			}
		}
	}
	if firstSeen.IsZero() {
		return "", time.Time{}, time.Time{}, false
	}
	if lastModified.IsZero() {
		lastModified = firstSeen
	}
	return source, firstSeen, lastModified, true
}

func MergeComment(desired, remote, source string) string {
	_, wantFirst, wantModified, ok := ParseCommentTimestamps(desired)
	if !ok {
		return desired
	}
	_, remoteFirst, _, remoteOK := ParseCommentTimestamps(remote)
	if !remoteOK || !remoteFirst.Before(wantFirst) {
		return desired
	}
	return BuildComment(source, remoteFirst, wantModified)
}

func (t *Tracker) CommentFor(domain, hostname, recordType, source string) string {
	if t == nil {
		return ""
	}
	if e := t.Get(domain, hostname, recordType); e != nil {
		return BuildComment(sourceOr(e.Source, source), e.FirstSeen, e.LastModified)
	}
	now := time.Now().UTC()
	return BuildComment(source, now, now)
}

func sourceOr(tracked, fallback string) string {
	if tracked != "" {
		return tracked
	}
	if fallback != "" {
		return fallback
	}
	return "herald"
}

func Get(domain, hostname, recordType string) *Entry {
	if Default != nil {
		return Default.Get(domain, hostname, recordType)
	}
	return nil
}

func CommentFor(domain, hostname, recordType, source string) string {
	if Default != nil {
		return Default.CommentFor(domain, hostname, recordType, source)
	}
	now := time.Now().UTC()
	return BuildComment(source, now, now)
}
