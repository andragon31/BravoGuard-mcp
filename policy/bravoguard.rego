# BRAVOGuard policy gates (T10, conftest v0.71.1).
#
# Evaluated over the scan findings JSON ({"findings": [...]}) via
# `conftest test --policy policy --output json <findings-file>`.
# `package main` is the conftest default namespace, so no --namespace flag
# is needed. `deny` blocks the verdict, `warn` only advises; the runner
# treats policy as advisory infrastructure that never fails a scan.
package main

# Block on any CRITICAL finding (verified live credentials, critical vulns).
deny contains msg if {
	some i
	finding := input.findings[i]
	finding.severity == "CRITICAL"
	msg := sprintf(
		"CRITICAL finding: %v at %v:%v",
		[finding.rule_id, finding.path, finding.line],
	)
}

# Block on verified live secrets even if a future normalizer stops marking
# them CRITICAL (defense in depth: the detector name is the signal).
deny contains msg if {
	some i
	finding := input.findings[i]
	startswith(finding.rule_id, "trufflehog-")
	finding.severity == "CRITICAL"
	msg := sprintf(
		"Verified live secret: %v at %v:%v",
		[finding.rule_id, finding.path, finding.line],
	)
}

# Advise on HIGH findings without remediation guidance.
warn contains msg if {
	some i
	finding := input.findings[i]
	finding.severity == "HIGH"
	finding.fix_hint == ""
	msg := sprintf(
		"HIGH without fix: %v at %v:%v",
		[finding.rule_id, finding.path, finding.line],
	)
}
