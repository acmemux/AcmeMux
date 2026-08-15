// Package compatibility classifies an audited upstream lego executable
// against immutable, source-backed manifests.
//
// A manifest is an exact identity allowlist, not a semantic-version range.
// It separates what the corresponding lego source compiles from the smaller
// CA, challenge, and DNS-provider catalog that AcmeMux has implemented and
// tested. Classification never executes lego and never performs network or
// certificate operations.
package compatibility
