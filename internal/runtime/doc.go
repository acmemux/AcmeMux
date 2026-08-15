// Package runtime establishes the trust boundary around an
// administrator-selected upstream lego executable.
//
// Inspection opens every path component without following symbolic links,
// audits the opened file, fingerprints its contents, and executes only that
// already-open file for the non-mutating --version probe. Compatibility with
// a particular upstream release or revision is deliberately decided by the
// compatibility package rather than here.
package runtime
