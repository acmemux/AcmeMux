package workspace

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	storeSelectionID            = 1
	maximumPersistedPaths       = 3 + maximumReferencedPaths
	maximumPersistedComponents  = 65536
	maximumPersistedDiagnostics = 1024
	maximumDiagnosticDetail     = 256
	maximumStoreYear            = 9999
)

var (
	// ErrNoSelection reports that no native workspace has been adopted.
	ErrNoSelection = errors.New("workspace is not selected")
	// ErrInvalidSelection identifies incomplete, inconsistent, or corrupted
	// reviewed evidence. Callers must never use such evidence for native I/O.
	ErrInvalidSelection = errors.New("workspace selection is invalid")
)

// Selection is the complete non-content review accepted by an administrator.
type Selection struct {
	Review     Review
	ReviewedAt time.Time
}

// StoreDatabase is the narrow application-state surface used by Store.
type StoreDatabase interface {
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
}

// Store persists one reviewed workspace and its ordered child evidence.
type Store struct {
	database StoreDatabase
}

// NewStore constructs a workspace selection store.
func NewStore(database StoreDatabase) (*Store, error) {
	if database == nil {
		return nil, errors.New("workspace selection database is required")
	}
	return &Store{database: database}, nil
}

// Save atomically replaces the singleton only after validating every field.
func (store *Store) Save(ctx context.Context, selection Selection) error {
	if err := store.ready(ctx); err != nil {
		return err
	}
	if err := validateSelection(selection); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSelection, err)
	}

	tx, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin workspace selection save: %w", err)
	}
	defer tx.Rollback()
	if err := saveSelectionInTransaction(ctx, tx, selection); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit workspace selection: %w", err)
	}
	return nil
}

// FinalizeEdit atomically replaces the reviewed workspace evidence and
// removes the matching native-edit recovery journal. The filesystem changes
// have already become active when this method is called; a failure therefore
// deliberately leaves the journal in place for explicit recovery.
func (store *Store) FinalizeEdit(ctx context.Context, selection Selection, transactionID string) error {
	if err := store.ready(ctx); err != nil {
		return err
	}
	if !validTransactionID(transactionID) {
		return errors.New("native edit transaction identifier is invalid")
	}
	if err := validateSelection(selection); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSelection, err)
	}

	tx, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin native edit finalization: %w", err)
	}
	defer tx.Rollback()
	var persistedID string
	if err := tx.QueryRowContext(ctx,
		"SELECT transaction_id FROM workspace_edit_journal WHERE singleton_id = ?",
		storeSelectionID,
	).Scan(&persistedID); err != nil {
		return fmt.Errorf("load native edit journal for finalization: %w", err)
	}
	if persistedID != transactionID {
		return errors.New("native edit journal changed before finalization")
	}
	if err := saveSelectionInTransaction(ctx, tx, selection); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx,
		"DELETE FROM workspace_edit_journal WHERE singleton_id = ? AND transaction_id = ?",
		storeSelectionID, transactionID,
	)
	if err != nil {
		return fmt.Errorf("clear finalized native edit journal: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return errors.New("native edit journal was not cleared during finalization")
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit native edit finalization: %w", err)
	}
	return nil
}

func saveSelectionInTransaction(ctx context.Context, tx *sql.Tx, selection Selection) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM workspace_selection WHERE singleton_id = ?", storeSelectionID); err != nil {
		return fmt.Errorf("replace workspace selection: %w", err)
	}
	review := selection.Review
	if _, err := tx.ExecContext(ctx, insertSelectionSQL,
		storeSelectionID,
		string(review.ConfigurationSource),
		boolInteger(review.Adoptable),
		review.ReviewedEvidenceSHA256,
		formatStoreTime(review.ObservedAt),
		formatStoreTime(selection.ReviewedAt),
	); err != nil {
		return fmt.Errorf("save workspace selection: %w", err)
	}

	for pathOrdinal, evidence := range review.AllPaths() {
		if _, err := tx.ExecContext(ctx, insertPathSQL,
			storeSelectionID,
			pathOrdinal,
			string(evidence.Role),
			evidence.Reference,
			evidence.Path,
			boolInteger(evidence.Exists),
			string(evidence.Type),
			strconv.FormatUint(evidence.Device, 10),
			strconv.FormatUint(evidence.Inode, 10),
			int64(evidence.Mode),
			int64(evidence.UID),
			int64(evidence.GID),
			strconv.FormatUint(evidence.NLink, 10),
			evidence.Size,
			formatStoreTime(evidence.ModifiedAt),
			formatStoreTime(evidence.ChangedAt),
			boolInteger(evidence.Access.Readable),
			boolInteger(evidence.Access.Writable),
			boolInteger(evidence.Access.Searchable),
			boolInteger(evidence.Safe),
		); err != nil {
			return fmt.Errorf("save workspace path %d: %w", pathOrdinal, err)
		}
		for componentOrdinal, component := range evidence.Components {
			// Component directory link counts are intentionally volatile and are
			// neither persisted nor bound by the administrator fingerprint.
			if _, err := tx.ExecContext(ctx, insertComponentSQL,
				storeSelectionID,
				pathOrdinal,
				componentOrdinal,
				component.Path,
				string(component.Type),
				strconv.FormatUint(component.Device, 10),
				strconv.FormatUint(component.Inode, 10),
				int64(component.Mode),
				int64(component.UID),
				int64(component.GID),
				boolInteger(component.Access.Readable),
				boolInteger(component.Access.Writable),
				boolInteger(component.Access.Searchable),
			); err != nil {
				return fmt.Errorf("save workspace component %d/%d: %w", pathOrdinal, componentOrdinal, err)
			}
		}
	}
	for ordinal, diagnostic := range review.Diagnostics {
		if _, err := tx.ExecContext(ctx, insertDiagnosticSQL,
			storeSelectionID,
			ordinal,
			string(diagnostic.Code),
			string(diagnostic.Severity),
			string(diagnostic.Role),
			diagnostic.Path,
			diagnostic.Component,
			diagnostic.Detail,
		); err != nil {
			return fmt.Errorf("save workspace diagnostic %d: %w", ordinal, err)
		}
	}
	return nil
}

// Load reconstructs a transactionally consistent selection and fails closed
// when any persisted type, order, bound, relationship, or digest is invalid.
func (store *Store) Load(ctx context.Context) (Selection, error) {
	if err := store.ready(ctx); err != nil {
		return Selection{}, err
	}
	tx, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return Selection{}, fmt.Errorf("begin workspace selection load: %w", err)
	}
	defer tx.Rollback()

	var persisted persistedSelection
	err = tx.QueryRowContext(ctx, loadSelectionSQL, storeSelectionID).Scan(
		&persisted.configurationSource,
		&persisted.adoptable,
		&persisted.fingerprint,
		&persisted.observedAt,
		&persisted.reviewedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Selection{}, ErrNoSelection
	}
	if err != nil {
		return Selection{}, fmt.Errorf("load workspace selection: %w", err)
	}
	selection, err := persisted.selection()
	if err != nil {
		return Selection{}, persistedInvalid(err)
	}

	paths, err := loadPersistedPaths(ctx, tx)
	if err != nil {
		return Selection{}, persistedInvalid(err)
	}
	if err := loadPersistedComponents(ctx, tx, paths); err != nil {
		return Selection{}, persistedInvalid(err)
	}
	diagnostics, err := loadPersistedDiagnostics(ctx, tx)
	if err != nil {
		return Selection{}, persistedInvalid(err)
	}
	if len(paths) < 3 {
		return Selection{}, persistedInvalid(errors.New("required workspace paths are missing"))
	}
	selection.Review.WorkingDirectory = paths[0]
	selection.Review.Configuration = paths[1]
	selection.Review.Storage = paths[2]
	seenWebroot := false
	for _, evidence := range paths[3:] {
		switch evidence.Role {
		case RoleDotenv:
			if seenWebroot {
				return Selection{}, persistedInvalid(errors.New("workspace path roles are out of order"))
			}
			selection.Review.DotenvFiles = append(selection.Review.DotenvFiles, evidence)
		case RoleWebroot:
			seenWebroot = true
			selection.Review.Webroots = append(selection.Review.Webroots, evidence)
		default:
			return Selection{}, persistedInvalid(errors.New("workspace path role is unexpected"))
		}
	}
	selection.Review.Diagnostics = diagnostics
	legacyFingerprint := ""
	currentFingerprint := ReviewFingerprint(selection.Review)
	if selection.Review.ReviewedEvidenceSHA256 != currentFingerprint {
		if selection.Review.ReviewedEvidenceSHA256 != legacyReviewFingerprintV1(selection.Review) {
			return Selection{}, persistedInvalid(errors.New("review fingerprint does not match persisted evidence"))
		}
		legacyFingerprint = selection.Review.ReviewedEvidenceSHA256
		selection.Review.ReviewedEvidenceSHA256 = currentFingerprint
	}
	if err := validateSelection(selection); err != nil {
		return Selection{}, persistedInvalid(err)
	}
	if legacyFingerprint != "" {
		result, updateErr := tx.ExecContext(ctx, `UPDATE workspace_selection
SET reviewed_evidence_sha256 = ?
WHERE singleton_id = ? AND reviewed_evidence_sha256 = ?`,
			currentFingerprint, storeSelectionID, legacyFingerprint,
		)
		if updateErr != nil {
			return Selection{}, fmt.Errorf("upgrade workspace review fingerprint: %w", updateErr)
		}
		if err := requireOneRow(result, "workspace review fingerprint upgrade"); err != nil {
			return Selection{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Selection{}, fmt.Errorf("finish workspace selection load: %w", err)
	}
	return selection, nil
}

// Clear transactionally removes the singleton and all cascading evidence.
func (store *Store) Clear(ctx context.Context) error {
	if err := store.ready(ctx); err != nil {
		return err
	}
	tx, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin workspace selection clear: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DELETE FROM workspace_selection WHERE singleton_id = ?", storeSelectionID); err != nil {
		return fmt.Errorf("clear workspace selection: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit workspace selection clear: %w", err)
	}
	return nil
}

func (store *Store) ready(ctx context.Context) error {
	if store == nil || store.database == nil {
		return errors.New("workspace selection store is not initialized")
	}
	if ctx == nil {
		return errors.New("workspace selection context is required")
	}
	return nil
}

type persistedSelection struct {
	configurationSource string
	adoptable           int64
	fingerprint         string
	observedAt          string
	reviewedAt          string
}

func (persisted persistedSelection) selection() (Selection, error) {
	adoptable, err := storedBoolean(persisted.adoptable, "adoptable")
	if err != nil {
		return Selection{}, err
	}
	observedAt, err := parseStoreTime(persisted.observedAt)
	if err != nil {
		return Selection{}, fmt.Errorf("observation time: %w", err)
	}
	reviewedAt, err := parseStoreTime(persisted.reviewedAt)
	if err != nil {
		return Selection{}, fmt.Errorf("review time: %w", err)
	}
	return Selection{
		Review: Review{
			ConfigurationSource:    ConfigurationSource(persisted.configurationSource),
			Adoptable:              adoptable,
			ReviewedEvidenceSHA256: persisted.fingerprint,
			ObservedAt:             observedAt,
		},
		ReviewedAt: reviewedAt,
	}, nil
}

type persistedPath struct {
	ordinal    int64
	role       string
	reference  string
	path       string
	exists     int64
	pathType   string
	device     string
	inode      string
	mode       int64
	uid        int64
	gid        int64
	nlink      string
	size       int64
	modifiedAt string
	changedAt  string
	readable   int64
	writable   int64
	searchable int64
	safe       int64
}

func (persisted persistedPath) evidence() (PathEvidence, error) {
	device, err := canonicalUint64(persisted.device, "device")
	if err != nil {
		return PathEvidence{}, err
	}
	inode, err := canonicalUint64(persisted.inode, "inode")
	if err != nil {
		return PathEvidence{}, err
	}
	nlink, err := canonicalUint64(persisted.nlink, "link count")
	if err != nil {
		return PathEvidence{}, err
	}
	mode, err := storedUint32(persisted.mode, "mode")
	if err != nil {
		return PathEvidence{}, err
	}
	uid, err := storedUint32(persisted.uid, "uid")
	if err != nil {
		return PathEvidence{}, err
	}
	gid, err := storedUint32(persisted.gid, "gid")
	if err != nil {
		return PathEvidence{}, err
	}
	modifiedAt, err := parseStoreTime(persisted.modifiedAt)
	if err != nil {
		return PathEvidence{}, fmt.Errorf("modified time: %w", err)
	}
	changedAt, err := parseStoreTime(persisted.changedAt)
	if err != nil {
		return PathEvidence{}, fmt.Errorf("changed time: %w", err)
	}
	exists, err := storedBoolean(persisted.exists, "exists")
	if err != nil {
		return PathEvidence{}, err
	}
	readable, err := storedBoolean(persisted.readable, "readable")
	if err != nil {
		return PathEvidence{}, err
	}
	writable, err := storedBoolean(persisted.writable, "writable")
	if err != nil {
		return PathEvidence{}, err
	}
	searchable, err := storedBoolean(persisted.searchable, "searchable")
	if err != nil {
		return PathEvidence{}, err
	}
	safe, err := storedBoolean(persisted.safe, "safe")
	if err != nil {
		return PathEvidence{}, err
	}
	return PathEvidence{
		Role:       PathRole(persisted.role),
		Reference:  persisted.reference,
		Path:       persisted.path,
		Exists:     exists,
		Type:       PathType(persisted.pathType),
		Device:     device,
		Inode:      inode,
		Mode:       mode,
		UID:        uid,
		GID:        gid,
		NLink:      nlink,
		Size:       persisted.size,
		ModifiedAt: modifiedAt,
		ChangedAt:  changedAt,
		Access: AccessEvidence{
			Readable: readable, Writable: writable, Searchable: searchable,
		},
		Safe: safe,
	}, nil
}

type persistedComponent struct {
	pathOrdinal      int64
	componentOrdinal int64
	path             string
	pathType         string
	device           string
	inode            string
	mode             int64
	uid              int64
	gid              int64
	readable         int64
	writable         int64
	searchable       int64
}

func (persisted persistedComponent) evidence() (ComponentEvidence, error) {
	device, err := canonicalUint64(persisted.device, "component device")
	if err != nil {
		return ComponentEvidence{}, err
	}
	inode, err := canonicalUint64(persisted.inode, "component inode")
	if err != nil {
		return ComponentEvidence{}, err
	}
	mode, err := storedUint32(persisted.mode, "component mode")
	if err != nil {
		return ComponentEvidence{}, err
	}
	uid, err := storedUint32(persisted.uid, "component uid")
	if err != nil {
		return ComponentEvidence{}, err
	}
	gid, err := storedUint32(persisted.gid, "component gid")
	if err != nil {
		return ComponentEvidence{}, err
	}
	readable, err := storedBoolean(persisted.readable, "component readable")
	if err != nil {
		return ComponentEvidence{}, err
	}
	writable, err := storedBoolean(persisted.writable, "component writable")
	if err != nil {
		return ComponentEvidence{}, err
	}
	searchable, err := storedBoolean(persisted.searchable, "component searchable")
	if err != nil {
		return ComponentEvidence{}, err
	}
	return ComponentEvidence{
		Path: persisted.path, Type: PathType(persisted.pathType), Device: device, Inode: inode,
		Mode: mode, UID: uid, GID: gid,
		Access: AccessEvidence{Readable: readable, Writable: writable, Searchable: searchable},
	}, nil
}

func loadPersistedPaths(ctx context.Context, tx *sql.Tx) ([]PathEvidence, error) {
	rows, err := tx.QueryContext(ctx, loadPathsSQL, storeSelectionID)
	if err != nil {
		return nil, fmt.Errorf("query workspace paths: %w", err)
	}
	defer rows.Close()
	var paths []PathEvidence
	for rows.Next() {
		if len(paths) >= maximumPersistedPaths {
			return nil, errors.New("workspace path count exceeds the persistence limit")
		}
		var persisted persistedPath
		if err := rows.Scan(
			&persisted.ordinal,
			&persisted.role,
			&persisted.reference,
			&persisted.path,
			&persisted.exists,
			&persisted.pathType,
			&persisted.device,
			&persisted.inode,
			&persisted.mode,
			&persisted.uid,
			&persisted.gid,
			&persisted.nlink,
			&persisted.size,
			&persisted.modifiedAt,
			&persisted.changedAt,
			&persisted.readable,
			&persisted.writable,
			&persisted.searchable,
			&persisted.safe,
		); err != nil {
			return nil, fmt.Errorf("scan workspace path: %w", err)
		}
		if persisted.ordinal != int64(len(paths)) {
			return nil, errors.New("workspace path ordinals are not contiguous")
		}
		evidence, err := persisted.evidence()
		if err != nil {
			return nil, err
		}
		paths = append(paths, evidence)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read workspace paths: %w", err)
	}
	return paths, nil
}

func loadPersistedComponents(ctx context.Context, tx *sql.Tx, paths []PathEvidence) error {
	rows, err := tx.QueryContext(ctx, loadComponentsSQL, storeSelectionID)
	if err != nil {
		return fmt.Errorf("query workspace components: %w", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		if count > maximumPersistedComponents {
			return errors.New("workspace component count exceeds the persistence limit")
		}
		var persisted persistedComponent
		if err := rows.Scan(
			&persisted.pathOrdinal,
			&persisted.componentOrdinal,
			&persisted.path,
			&persisted.pathType,
			&persisted.device,
			&persisted.inode,
			&persisted.mode,
			&persisted.uid,
			&persisted.gid,
			&persisted.readable,
			&persisted.writable,
			&persisted.searchable,
		); err != nil {
			return fmt.Errorf("scan workspace component: %w", err)
		}
		if persisted.pathOrdinal < 0 || persisted.pathOrdinal >= int64(len(paths)) {
			return errors.New("workspace component references an unknown path")
		}
		components := &paths[persisted.pathOrdinal].Components
		if persisted.componentOrdinal != int64(len(*components)) {
			return errors.New("workspace component ordinals are not contiguous")
		}
		if len(*components) >= maximumRecordedPathComponents {
			return errors.New("workspace path has too many components")
		}
		evidence, err := persisted.evidence()
		if err != nil {
			return err
		}
		*components = append(*components, evidence)
	}
	return rows.Err()
}

func loadPersistedDiagnostics(ctx context.Context, tx *sql.Tx) ([]Diagnostic, error) {
	rows, err := tx.QueryContext(ctx, loadDiagnosticsSQL, storeSelectionID)
	if err != nil {
		return nil, fmt.Errorf("query workspace diagnostics: %w", err)
	}
	defer rows.Close()
	var diagnostics []Diagnostic
	for rows.Next() {
		if len(diagnostics) >= maximumPersistedDiagnostics {
			return nil, errors.New("workspace diagnostic count exceeds the persistence limit")
		}
		var (
			ordinal   int64
			code      string
			severity  string
			role      string
			path      string
			component string
			detail    string
		)
		if err := rows.Scan(&ordinal, &code, &severity, &role, &path, &component, &detail); err != nil {
			return nil, fmt.Errorf("scan workspace diagnostic: %w", err)
		}
		if ordinal != int64(len(diagnostics)) {
			return nil, errors.New("workspace diagnostic ordinals are not contiguous")
		}
		diagnostics = append(diagnostics, Diagnostic{
			Code: ErrorCode(code), Severity: DiagnosticSeverity(severity), Role: PathRole(role),
			Path: path, Component: component, Detail: detail,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read workspace diagnostics: %w", err)
	}
	return diagnostics, nil
}

func validateSelection(selection Selection) error {
	review := selection.Review
	if !review.Adoptable {
		return errors.New("review is not adoptable")
	}
	if err := validateStoreTime(review.ObservedAt); err != nil {
		return fmt.Errorf("observation time: %w", err)
	}
	if err := validateStoreTime(selection.ReviewedAt); err != nil {
		return fmt.Errorf("review time: %w", err)
	}
	if selection.ReviewedAt.Before(review.ObservedAt) {
		return errors.New("review time precedes observation time")
	}
	if !canonicalDigest(review.ReviewedEvidenceSHA256) {
		return errors.New("review fingerprint is not canonical lowercase SHA-256")
	}
	if ReviewFingerprint(review) != review.ReviewedEvidenceSHA256 {
		return errors.New("review fingerprint does not match the persisted evidence")
	}
	if len(review.DotenvFiles)+len(review.Webroots) > maximumReferencedPaths {
		return errors.New("referenced path count exceeds the persistence limit")
	}
	if len(review.AllPaths()) > maximumPersistedPaths {
		return errors.New("workspace path count exceeds the persistence limit")
	}
	if len(review.Diagnostics) > maximumPersistedDiagnostics {
		return errors.New("workspace diagnostic count exceeds the persistence limit")
	}

	working := review.WorkingDirectory
	configuration := review.Configuration
	if err := validateCanonicalStorePath(working.Path); err != nil {
		return fmt.Errorf("working directory: %w", err)
	}
	if err := validateCanonicalStorePath(configuration.Path); err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	switch review.ConfigurationSource {
	case ConfigurationExplicit:
	case ConfigurationConventionalYML:
		if configuration.Path != filepath.Join(working.Path, ".lego.yml") {
			return errors.New("conventional .lego.yml path disagrees with the working directory")
		}
	case ConfigurationConventionalYAML:
		if configuration.Path != filepath.Join(working.Path, ".lego.yaml") {
			return errors.New("conventional .lego.yaml path disagrees with the working directory")
		}
	default:
		return errors.New("configuration source is unknown")
	}
	if len(working.Components) == 0 {
		return errors.New("working-directory component evidence is missing")
	}
	if configuration.UID == working.Components[0].UID {
		return errors.New("configuration owner cannot be the trusted filesystem-root identity")
	}
	rootUID := working.Components[0].UID
	serviceUID := configuration.UID
	rootComponent := working.Components[0]

	paths := review.AllPaths()
	componentCount := 0
	for index := range paths {
		expectedRole := RoleDotenv
		switch {
		case index == 0:
			expectedRole = RoleWorkingDirectory
		case index == 1:
			expectedRole = RoleConfiguration
		case index == 2:
			expectedRole = RoleStorage
		case index >= 3+len(review.DotenvFiles):
			expectedRole = RoleWebroot
		}
		if err := validatePathEvidence(paths[index], expectedRole, working.Path, rootUID, serviceUID, rootComponent); err != nil {
			return fmt.Errorf("path %d: %w", index, err)
		}
		componentCount += len(paths[index].Components)
		if componentCount > maximumPersistedComponents {
			return errors.New("workspace component count exceeds the persistence limit")
		}
	}
	if err := validateReferenceOrder(review.DotenvFiles); err != nil {
		return fmt.Errorf("dotenv paths: %w", err)
	}
	if err := validateReferenceOrder(review.Webroots); err != nil {
		return fmt.Errorf("webroot paths: %w", err)
	}
	if err := validateDiagnostics(review); err != nil {
		return err
	}
	return nil
}

func validatePathEvidence(evidence PathEvidence, expectedRole PathRole, workingDirectory string, rootUID, serviceUID uint32, root ComponentEvidence) error {
	if evidence.Role != expectedRole {
		return errors.New("path role is out of order")
	}
	if err := validateCanonicalStorePath(evidence.Path); err != nil {
		return err
	}
	if !evidence.Exists || !evidence.Safe {
		return errors.New("path is not present and safe")
	}
	if evidence.Size < 0 || evidence.NLink == 0 {
		return errors.New("path size or link count is invalid")
	}
	if err := validateStoreTime(evidence.ModifiedAt); err != nil {
		return fmt.Errorf("modified time: %w", err)
	}
	if err := validateStoreTime(evidence.ChangedAt); err != nil {
		return fmt.Errorf("changed time: %w", err)
	}
	if len(evidence.Components) == 0 || len(evidence.Components) > maximumRecordedPathComponents {
		return errors.New("component count is invalid")
	}
	if expected := expectedComponentPaths(evidence.Path); len(evidence.Components) != len(expected) {
		return errors.New("component count disagrees with the canonical path")
	} else {
		for index, component := range evidence.Components {
			if component.Path != expected[index] {
				return errors.New("component path disagrees with the canonical path")
			}
			final := index == len(evidence.Components)-1
			if err := validateComponent(component, final, rootUID, serviceUID); err != nil {
				return fmt.Errorf("component %d: %w", index, err)
			}
		}
	}
	if !sameStableComponent(root, evidence.Components[0]) {
		return errors.New("filesystem-root evidence is inconsistent")
	}
	final := evidence.Components[len(evidence.Components)-1]
	if final.Path != evidence.Path || final.Type != evidence.Type || final.Device != evidence.Device ||
		final.Inode != evidence.Inode || final.Mode != evidence.Mode || final.UID != evidence.UID ||
		final.GID != evidence.GID || final.Access != evidence.Access {
		return errors.New("final component disagrees with path evidence")
	}
	if err := validateModeType(evidence.Mode, evidence.Type); err != nil {
		return err
	}

	switch expectedRole {
	case RoleWorkingDirectory:
		if evidence.Reference != "" || evidence.Type != PathTypeDirectory || !evidence.Access.Readable || !evidence.Access.Searchable {
			return errors.New("working-directory evidence is inconsistent")
		}
	case RoleConfiguration:
		if evidence.Reference != "" {
			return errors.New("configuration contains a native reference")
		}
		if err := validateConfidentialFile(evidence, serviceUID); err != nil {
			return err
		}
		if err := validateReplacementParent(evidence); err != nil {
			return err
		}
	case RoleStorage:
		if err := validateNativeReference(evidence, workingDirectory); err != nil {
			return err
		}
		if evidence.Type != PathTypeDirectory || !evidence.Access.Readable || !evidence.Access.Writable || !evidence.Access.Searchable {
			return errors.New("storage access evidence is inconsistent")
		}
	case RoleDotenv:
		if err := validateNativeReference(evidence, workingDirectory); err != nil {
			return err
		}
		if err := validateConfidentialFile(evidence, serviceUID); err != nil {
			return err
		}
		if err := validateReplacementParent(evidence); err != nil {
			return err
		}
	case RoleWebroot:
		if err := validateNativeReference(evidence, workingDirectory); err != nil {
			return err
		}
		if evidence.Type != PathTypeDirectory || !evidence.Access.Writable || !evidence.Access.Searchable {
			return errors.New("webroot access evidence is inconsistent")
		}
	default:
		return errors.New("path role is unknown")
	}
	return nil
}

func validateComponent(component ComponentEvidence, final bool, rootUID, serviceUID uint32) error {
	if err := validateCanonicalStorePath(component.Path); err != nil {
		return err
	}
	if component.UID != rootUID && component.UID != serviceUID {
		return errors.New("component owner is outside the reviewed identity boundary")
	}
	if err := validateModeType(component.Mode, component.Type); err != nil {
		return err
	}
	if !final && component.Type != PathTypeDirectory {
		return errors.New("non-final component is not a directory")
	}
	permissions := component.Mode & 0o7777
	rootStickyAncestor := !final && component.UID == rootUID && permissions&0o1000 != 0
	if permissions&0o022 != 0 && !rootStickyAncestor {
		return errors.New("component permits group or other writes")
	}
	if permissions&0o6000 != 0 || permissions&0o1000 != 0 && !rootStickyAncestor {
		return errors.New("component contains unsafe special permission bits")
	}
	if component.Type == PathTypeDirectory && !component.Access.Searchable {
		return errors.New("component is not searchable")
	}
	if component.Type == PathTypeRegular && component.Access.Searchable {
		return errors.New("regular-file component is marked searchable")
	}
	if component.UID == serviceUID {
		owner := (component.Mode >> 6) & 0o7
		want := AccessEvidence{
			Readable:   owner&0o4 != 0,
			Writable:   owner&0o2 != 0,
			Searchable: component.Type == PathTypeDirectory && owner&0o1 != 0,
		}
		if component.Access != want {
			return errors.New("service-owned component access disagrees with its mode")
		}
	} else {
		group := (component.Mode >> 3) & 0o7
		other := component.Mode & 0o7
		if (component.Access.Readable && group&0o4 == 0 && other&0o4 == 0) || (!component.Access.Readable && other&0o4 != 0) {
			return errors.New("root-owned component read access disagrees with its mode")
		}
		if (component.Access.Writable && group&0o2 == 0 && other&0o2 == 0) || (!component.Access.Writable && other&0o2 != 0) {
			return errors.New("root-owned component write access disagrees with its mode")
		}
		if (component.Access.Searchable && group&0o1 == 0 && other&0o1 == 0) ||
			(!component.Access.Searchable && component.Type == PathTypeDirectory && other&0o1 != 0) {
			return errors.New("root-owned component search access disagrees with its mode")
		}
	}
	return nil
}

func validateModeType(mode uint32, pathType PathType) error {
	const modeTypeMask = uint32(0o170000)
	switch pathType {
	case PathTypeDirectory:
		if mode&modeTypeMask != 0o040000 {
			return errors.New("directory type disagrees with mode")
		}
	case PathTypeRegular:
		if mode&modeTypeMask != 0o100000 {
			return errors.New("regular-file type disagrees with mode")
		}
	default:
		return errors.New("path type is not persistable")
	}
	return nil
}

func validateConfidentialFile(evidence PathEvidence, serviceUID uint32) error {
	if evidence.Type != PathTypeRegular || evidence.NLink != 1 || evidence.UID != serviceUID {
		return errors.New("confidential file type, owner, or link count is invalid")
	}
	if evidence.Mode&0o077 != 0 {
		return errors.New("confidential file grants group or other permissions")
	}
	if !evidence.Access.Readable {
		return errors.New("confidential file is not service-readable")
	}
	return nil
}

func validateReplacementParent(evidence PathEvidence) error {
	if len(evidence.Components) < 2 {
		return errors.New("replacement parent is missing")
	}
	parent := evidence.Components[len(evidence.Components)-2]
	if parent.Type != PathTypeDirectory || !parent.Access.Writable || !parent.Access.Searchable {
		return errors.New("replacement parent is not writable and searchable")
	}
	return nil
}

func validateNativeReference(evidence PathEvidence, workingDirectory string) error {
	if err := validateStoredReference(evidence.Reference); err != nil {
		return err
	}
	resolved, err := resolveNativePath(workingDirectory, evidence.Reference)
	if err != nil || resolved != evidence.Path {
		return errors.New("native reference disagrees with the resolved path")
	}
	return nil
}

func validateReferenceOrder(paths []PathEvidence) error {
	for index := 1; index < len(paths); index++ {
		left, right := paths[index-1], paths[index]
		if left.Path > right.Path || left.Path == right.Path && left.Reference > right.Reference {
			return errors.New("referenced paths are not in canonical order")
		}
	}
	return nil
}

func validateDiagnostics(review Review) error {
	if len(review.Diagnostics) > 1 {
		return errors.New("adoptable review has unexpected diagnostics")
	}
	for _, diagnostic := range review.Diagnostics {
		if len(diagnostic.Detail) == 0 || len(diagnostic.Detail) > maximumDiagnosticDetail {
			return errors.New("adoptable review diagnostic detail is not bounded")
		}
		if diagnostic.Code != CodeConfigurationPrecedence || diagnostic.Severity != SeverityNotice ||
			diagnostic.Role != RoleConfiguration || review.ConfigurationSource != ConfigurationConventionalYML ||
			diagnostic.Path != review.Configuration.Path ||
			diagnostic.Component != filepath.Join(review.WorkingDirectory.Path, ".lego.yaml") ||
			diagnostic.Detail != "both conventional names exist; .lego.yml takes precedence" {
			return errors.New("adoptable review contains an invalid diagnostic")
		}
	}
	return nil
}

func sameStableComponent(left, right ComponentEvidence) bool {
	left.NLink = 0
	right.NLink = 0
	return reflect.DeepEqual(left, right)
}

func expectedComponentPaths(path string) []string {
	result := []string{"/"}
	if path == "/" {
		return result
	}
	prefix := "/"
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		prefix = filepath.Join(prefix, component)
		result = append(result, prefix)
	}
	return result
}

func validateCanonicalStorePath(value string) error {
	if value == "" || len(value) > maximumPathBytes || !utf8.ValidString(value) || strings.IndexFunc(value, invalidPathRune) >= 0 {
		return errors.New("canonical path has invalid text or length")
	}
	if !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return errors.New("path is not canonical and absolute")
	}
	return nil
}

func validateStoredReference(value string) error {
	if value == "" || len(value) > maximumPathBytes || !utf8.ValidString(value) || strings.IndexFunc(value, invalidPathRune) >= 0 {
		return errors.New("native reference has invalid text or length")
	}
	return nil
}

func validateStoreTime(value time.Time) error {
	if value.IsZero() || value.Location() != time.UTC || value.Year() < 1 || value.Year() > maximumStoreYear {
		return errors.New("timestamp must be nonzero UTC time")
	}
	if value != value.Round(0) {
		return errors.New("timestamp contains monotonic data")
	}
	return nil
}

func formatStoreTime(value time.Time) string { return value.Format(time.RFC3339Nano) }

func parseStoreTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("timestamp is not canonical UTC RFC 3339 nanosecond text")
	}
	if err := validateStoreTime(parsed); err != nil {
		return time.Time{}, err
	}
	return parsed, nil
}

func canonicalUint64(value, name string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != value {
		return 0, fmt.Errorf("%s is not canonical unsigned decimal", name)
	}
	return parsed, nil
}

func storedUint32(value int64, name string) (uint32, error) {
	if value < 0 || value > int64(^uint32(0)) {
		return 0, fmt.Errorf("%s is outside unsigned 32-bit range", name)
	}
	return uint32(value), nil
}

func storedBoolean(value int64, name string) (bool, error) {
	switch value {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("%s is not Boolean", name)
	}
}

func boolInteger(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func canonicalDigest(value string) bool {
	return len(value) == 64 && strings.IndexFunc(value, func(character rune) bool {
		return (character < '0' || character > '9') && (character < 'a' || character > 'f')
	}) < 0
}

func persistedInvalid(err error) error {
	return fmt.Errorf("%w: persisted metadata: %v", ErrInvalidSelection, err)
}

const insertSelectionSQL = `
INSERT INTO workspace_selection (
    singleton_id, configuration_source, adoptable, reviewed_evidence_sha256,
    observed_at_utc, reviewed_at_utc
) VALUES (?, ?, ?, ?, ?, ?)`

const insertPathSQL = `
INSERT INTO workspace_path_observation (
    selection_id, path_ordinal, role, reference_text, canonical_path,
    exists_flag, path_type, device_decimal, inode_decimal, mode, uid, gid,
    nlink_decimal, size_bytes, modified_at_utc, changed_at_utc,
    readable, writable, searchable, safe_flag
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

const insertComponentSQL = `
INSERT INTO workspace_component_observation (
    selection_id, path_ordinal, component_ordinal, canonical_path, path_type,
    device_decimal, inode_decimal, mode, uid, gid, readable, writable, searchable
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

const insertDiagnosticSQL = `
INSERT INTO workspace_review_diagnostic (
    selection_id, diagnostic_ordinal, code, severity, role,
    path_text, component_text, detail
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

const loadSelectionSQL = `
SELECT configuration_source, adoptable, reviewed_evidence_sha256,
       observed_at_utc, reviewed_at_utc
FROM workspace_selection
WHERE singleton_id = ?`

const loadPathsSQL = `
SELECT path_ordinal, role, reference_text, canonical_path, exists_flag,
       path_type, device_decimal, inode_decimal, mode, uid, gid,
       nlink_decimal, size_bytes, modified_at_utc, changed_at_utc,
       readable, writable, searchable, safe_flag
FROM workspace_path_observation
WHERE selection_id = ?
ORDER BY path_ordinal`

const loadComponentsSQL = `
SELECT path_ordinal, component_ordinal, canonical_path, path_type,
       device_decimal, inode_decimal, mode, uid, gid,
       readable, writable, searchable
FROM workspace_component_observation
WHERE selection_id = ?
ORDER BY path_ordinal, component_ordinal`

const loadDiagnosticsSQL = `
SELECT diagnostic_ordinal, code, severity, role,
       path_text, component_text, detail
FROM workspace_review_diagnostic
WHERE selection_id = ?
ORDER BY diagnostic_ordinal`
