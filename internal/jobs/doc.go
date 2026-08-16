// Package jobs owns the latest-only durable manual native-workspace operation
// and its single service-lifetime worker. Browser requests commit work but do
// not own its lifetime. Native execution remains behind Executor so jobs never
// receives raw child bytes, secrets, executable handles, or workspace files.
package jobs
