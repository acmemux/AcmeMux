package workspace

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// JournalStore persists the singleton secret-free native-edit recovery marker.
type JournalStore struct {
	database StoreDatabase
}

// NewJournalStore constructs a durable journal store.
func NewJournalStore(database StoreDatabase) (*JournalStore, error) {
	if database == nil {
		return nil, errors.New("native edit journal database is required")
	}
	return &JournalStore{database: database}, nil
}

// NewTransactionID returns 128 bits of lowercase random journal identity.
func NewTransactionID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate native edit transaction identifier: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

// Create inserts the complete planned journal before any candidate is written.
func (store *JournalStore) Create(ctx context.Context, journal Journal) error {
	if err := store.ready(ctx); err != nil {
		return err
	}
	if err := validateJournal(journal); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEdit, err)
	}
	tx, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin native edit journal: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO workspace_edit_journal (
singleton_id, transaction_id, phase, working_directory, configuration_path, created_at_utc
) VALUES (?, ?, ?, ?, ?, ?)`,
		storeSelectionID, journal.TransactionID, string(journal.Phase), journal.WorkingDirectory,
		journal.ConfigurationPath, formatStoreTime(journal.CreatedAt),
	); err != nil {
		return fmt.Errorf("create native edit journal: %w", err)
	}
	for _, file := range journal.Files {
		if _, err := tx.ExecContext(ctx, insertJournalFileSQL,
			storeSelectionID, file.Ordinal, string(file.Role), file.TargetPath, file.ParentPath,
			file.StageBasename, boolInteger(file.Original.Exists),
			strconv.FormatUint(file.Parent.Device, 10), strconv.FormatUint(file.Parent.Inode, 10),
			strconv.FormatUint(file.Original.Device, 10), strconv.FormatUint(file.Original.Inode, 10),
			int64(file.Original.Mode), int64(file.Original.UID), int64(file.Original.GID),
			strconv.FormatUint(file.Original.NLink, 10), file.Original.Size,
			formatOptionalTime(file.Original.ModifiedAt), formatOptionalTime(file.Original.ChangedAt),
		); err != nil {
			return fmt.Errorf("create native edit journal file %d: %w", file.Ordinal, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit native edit journal: %w", err)
	}
	return nil
}

// Load returns the complete singleton journal or ErrNoEditJournal.
func (store *JournalStore) Load(ctx context.Context) (Journal, error) {
	if err := store.ready(ctx); err != nil {
		return Journal{}, err
	}
	tx, err := store.database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Journal{}, fmt.Errorf("begin native edit journal load: %w", err)
	}
	defer tx.Rollback()
	var (
		transactionID string
		phase         string
		working       string
		configuration string
		created       string
	)
	err = tx.QueryRowContext(ctx, `SELECT transaction_id, phase, working_directory,
configuration_path, created_at_utc FROM workspace_edit_journal WHERE singleton_id = ?`,
		storeSelectionID,
	).Scan(&transactionID, &phase, &working, &configuration, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return Journal{}, ErrNoEditJournal
	}
	if err != nil {
		return Journal{}, fmt.Errorf("load native edit journal: %w", err)
	}
	createdAt, err := parseStoreTime(created)
	if err != nil {
		return Journal{}, fmt.Errorf("invalid native edit journal creation time")
	}
	journal := Journal{
		TransactionID: transactionID, Phase: JournalPhase(phase), WorkingDirectory: working,
		ConfigurationPath: configuration, CreatedAt: createdAt,
	}
	rows, err := tx.QueryContext(ctx, loadJournalFilesSQL, storeSelectionID)
	if err != nil {
		return Journal{}, fmt.Errorf("query native edit journal files: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		if len(journal.Files) >= maximumEditFiles {
			return Journal{}, errors.New("native edit journal contains too many files")
		}
		persisted := persistedJournalFile{}
		if err := rows.Scan(
			&persisted.ordinal, &persisted.role, &persisted.targetPath, &persisted.parentPath,
			&persisted.stageBasename, &persisted.targetExisted,
			&persisted.parentDevice, &persisted.parentInode,
			&persisted.originalDevice, &persisted.originalInode, &persisted.originalMode,
			&persisted.originalUID, &persisted.originalGID, &persisted.originalNLink,
			&persisted.originalSize, &persisted.originalModified, &persisted.originalChanged,
			&persisted.candidateReady, &persisted.candidateDevice, &persisted.candidateInode,
			&persisted.candidateMode, &persisted.candidateUID, &persisted.candidateGID,
			&persisted.candidateNLink, &persisted.candidateSize,
			&persisted.candidateModified, &persisted.candidateChanged, &persisted.applied,
		); err != nil {
			return Journal{}, fmt.Errorf("scan native edit journal file: %w", err)
		}
		if persisted.ordinal != int64(len(journal.Files)) {
			return Journal{}, errors.New("native edit journal file ordinals are invalid")
		}
		file, err := persisted.file()
		if err != nil {
			return Journal{}, fmt.Errorf("invalid native edit journal file %d", persisted.ordinal)
		}
		journal.Files = append(journal.Files, file)
	}
	if err := rows.Err(); err != nil {
		return Journal{}, fmt.Errorf("read native edit journal files: %w", err)
	}
	if err := validateJournal(journal); err != nil {
		return Journal{}, fmt.Errorf("invalid persisted native edit journal: %v", err)
	}
	if err := tx.Commit(); err != nil {
		return Journal{}, fmt.Errorf("finish native edit journal load: %w", err)
	}
	return journal, nil
}

// SetPhase advances the matching transaction monotonically.
func (store *JournalStore) SetPhase(ctx context.Context, transactionID string, phase JournalPhase) error {
	if err := store.ready(ctx); err != nil {
		return err
	}
	if !validTransactionID(transactionID) || !validJournalPhase(phase) {
		return fmt.Errorf("%w: invalid journal phase update", ErrInvalidEdit)
	}
	journal, err := store.Load(ctx)
	if err != nil {
		return err
	}
	if journal.TransactionID != transactionID || journalPhaseOrder(phase) < journalPhaseOrder(journal.Phase) {
		return fmt.Errorf("%w: journal phase is stale", ErrSourceChanged)
	}
	result, err := store.exec(ctx, `UPDATE workspace_edit_journal SET phase = ?
WHERE singleton_id = ? AND transaction_id = ?`, string(phase), storeSelectionID, transactionID)
	if err != nil {
		return fmt.Errorf("update native edit journal phase: %w", err)
	}
	return requireOneRow(result, "native edit journal phase")
}

// MarkCandidate records only the staged inode and metadata after file and
// directory synchronization. It never persists the candidate digest.
func (store *JournalStore) MarkCandidate(ctx context.Context, transactionID string, ordinal int, identity FileIdentity) error {
	if err := store.ready(ctx); err != nil {
		return err
	}
	if !validTransactionID(transactionID) || ordinal < 0 || ordinal >= maximumEditFiles ||
		!validCandidateIdentity(identity) {
		return fmt.Errorf("%w: invalid staged candidate evidence", ErrInvalidEdit)
	}
	result, err := store.exec(ctx, `UPDATE workspace_edit_journal_file SET
candidate_ready = 1, candidate_device_decimal = ?, candidate_inode_decimal = ?,
candidate_mode = ?, candidate_uid = ?, candidate_gid = ?, candidate_nlink_decimal = ?,
candidate_size_bytes = ?, candidate_modified_at_utc = ?, candidate_changed_at_utc = ?
WHERE journal_id = ? AND file_ordinal = ?
AND EXISTS (SELECT 1 FROM workspace_edit_journal WHERE singleton_id = ? AND transaction_id = ?)`,
		strconv.FormatUint(identity.Device, 10), strconv.FormatUint(identity.Inode, 10),
		int64(identity.Mode), int64(identity.UID), int64(identity.GID), strconv.FormatUint(identity.NLink, 10),
		identity.Size, formatStoreTime(identity.ModifiedAt), formatStoreTime(identity.ChangedAt),
		storeSelectionID, ordinal, storeSelectionID, transactionID,
	)
	if err != nil {
		return fmt.Errorf("record staged native edit candidate: %w", err)
	}
	return requireOneRow(result, "staged native edit candidate")
}

// MarkPlacement records post-rename target and displaced-original metadata.
// Rename changes ctime, so recovery must bind actual placements rather than
// their staged values even before the directory sync/applied marker completes.
func (store *JournalStore) MarkPlacement(
	ctx context.Context,
	transactionID string,
	ordinal int,
	candidate FileIdentity,
	original FileIdentity,
) error {
	return store.recordPlacement(ctx, transactionID, ordinal, candidate, original, false)
}

// MarkApplied records the synchronized active placement.
func (store *JournalStore) MarkApplied(
	ctx context.Context,
	transactionID string,
	ordinal int,
	candidate FileIdentity,
	original FileIdentity,
) error {
	return store.recordPlacement(ctx, transactionID, ordinal, candidate, original, true)
}

func (store *JournalStore) recordPlacement(
	ctx context.Context,
	transactionID string,
	ordinal int,
	candidate FileIdentity,
	original FileIdentity,
	applied bool,
) error {
	if err := store.ready(ctx); err != nil {
		return err
	}
	if !validTransactionID(transactionID) || ordinal < 0 || ordinal >= maximumEditFiles {
		return fmt.Errorf("%w: invalid applied journal record", ErrInvalidEdit)
	}
	if !validCandidateIdentity(candidate) || original.Exists && !validOriginalIdentity(original) ||
		!original.Exists && !zeroMissingIdentity(original) {
		return fmt.Errorf("%w: invalid applied placement evidence", ErrInvalidEdit)
	}
	result, err := store.exec(ctx, `UPDATE workspace_edit_journal_file SET
applied = ?,
candidate_device_decimal = ?, candidate_inode_decimal = ?, candidate_mode = ?,
candidate_uid = ?, candidate_gid = ?, candidate_nlink_decimal = ?,
candidate_size_bytes = ?, candidate_modified_at_utc = ?, candidate_changed_at_utc = ?,
original_device_decimal = ?, original_inode_decimal = ?, original_mode = ?,
original_uid = ?, original_gid = ?, original_nlink_decimal = ?,
original_size_bytes = ?, original_modified_at_utc = ?, original_changed_at_utc = ?
WHERE journal_id = ? AND file_ordinal = ? AND candidate_ready = 1
AND EXISTS (SELECT 1 FROM workspace_edit_journal WHERE singleton_id = ? AND transaction_id = ?)`,
		boolInteger(applied),
		strconv.FormatUint(candidate.Device, 10), strconv.FormatUint(candidate.Inode, 10), int64(candidate.Mode),
		int64(candidate.UID), int64(candidate.GID), strconv.FormatUint(candidate.NLink, 10),
		candidate.Size, formatStoreTime(candidate.ModifiedAt), formatStoreTime(candidate.ChangedAt),
		strconv.FormatUint(original.Device, 10), strconv.FormatUint(original.Inode, 10), int64(original.Mode),
		int64(original.UID), int64(original.GID), strconv.FormatUint(original.NLink, 10),
		original.Size, formatOptionalTime(original.ModifiedAt), formatOptionalTime(original.ChangedAt),
		storeSelectionID, ordinal, storeSelectionID, transactionID,
	)
	if err != nil {
		return fmt.Errorf("record native edit placement: %w", err)
	}
	return requireOneRow(result, "native edit placement")
}

// Clear removes an explicitly resolved journal.
func (store *JournalStore) Clear(ctx context.Context, transactionID string) error {
	if err := store.ready(ctx); err != nil {
		return err
	}
	if !validTransactionID(transactionID) {
		return fmt.Errorf("%w: invalid journal clear", ErrInvalidEdit)
	}
	result, err := store.exec(ctx, `DELETE FROM workspace_edit_journal
WHERE singleton_id = ? AND transaction_id = ?`, storeSelectionID, transactionID)
	if err != nil {
		return fmt.Errorf("clear native edit journal: %w", err)
	}
	return requireOneRow(result, "native edit journal")
}

func (store *JournalStore) ready(ctx context.Context) error {
	if store == nil || store.database == nil {
		return errors.New("native edit journal store is not initialized")
	}
	if ctx == nil {
		return errors.New("native edit journal context is required")
	}
	return nil
}

func (store *JournalStore) exec(ctx context.Context, query string, arguments ...any) (sql.Result, error) {
	tx, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, query, arguments...)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func requireOneRow(result sql.Result, name string) error {
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return fmt.Errorf("%s changed concurrently", name)
	}
	return nil
}

type persistedJournalFile struct {
	ordinal, targetExisted, originalMode, originalUID, originalGID, originalSize int64
	role, targetPath, parentPath, stageBasename                                  string
	parentDevice, parentInode                                                    string
	originalDevice, originalInode, originalNLink                                 string
	originalModified, originalChanged                                            string
	candidateReady, candidateMode, candidateUID, candidateGID, candidateSize     int64
	candidateDevice, candidateInode, candidateNLink                              string
	candidateModified, candidateChanged                                          string
	applied                                                                      int64
}

func (persisted persistedJournalFile) file() (JournalFile, error) {
	parentDevice, err := canonicalUint64(persisted.parentDevice, "parent device")
	if err != nil {
		return JournalFile{}, err
	}
	parentInode, err := canonicalUint64(persisted.parentInode, "parent inode")
	if err != nil {
		return JournalFile{}, err
	}
	// Only parent device/inode placement is durable journal evidence.
	parent := FileIdentity{Exists: true, Device: parentDevice, Inode: parentInode}
	existed, err := storedBoolean(persisted.targetExisted, "target existed")
	if err != nil {
		return JournalFile{}, err
	}
	original, err := persistedIdentity(existed, persisted.originalDevice, persisted.originalInode,
		uint32(persisted.originalMode), uint32(persisted.originalUID), uint32(persisted.originalGID),
		persisted.originalNLink, persisted.originalSize, persisted.originalModified, persisted.originalChanged)
	if err != nil {
		return JournalFile{}, err
	}
	ready, err := storedBoolean(persisted.candidateReady, "candidate ready")
	if err != nil {
		return JournalFile{}, err
	}
	candidate, err := persistedIdentity(ready, persisted.candidateDevice, persisted.candidateInode,
		uint32(persisted.candidateMode), uint32(persisted.candidateUID), uint32(persisted.candidateGID),
		persisted.candidateNLink, persisted.candidateSize, persisted.candidateModified, persisted.candidateChanged)
	if err != nil {
		return JournalFile{}, err
	}
	applied, err := storedBoolean(persisted.applied, "applied")
	if err != nil {
		return JournalFile{}, err
	}
	return JournalFile{
		Ordinal: int(persisted.ordinal), Role: PathRole(persisted.role), TargetPath: persisted.targetPath,
		ParentPath: persisted.parentPath, StageBasename: persisted.stageBasename,
		Original: original, Parent: parent, CandidateReady: ready, Candidate: candidate, Applied: applied,
	}, nil
}

func persistedIdentity(exists bool, deviceText, inodeText string, mode, uid, gid uint32,
	nlinkText string, size int64, modifiedText, changedText string,
) (FileIdentity, error) {
	device, err := canonicalUint64(deviceText, "device")
	if err != nil {
		return FileIdentity{}, err
	}
	inode, err := canonicalUint64(inodeText, "inode")
	if err != nil {
		return FileIdentity{}, err
	}
	nlink, err := canonicalUint64(nlinkText, "link count")
	if err != nil {
		return FileIdentity{}, err
	}
	identity := FileIdentity{Exists: exists, Device: device, Inode: inode, Mode: mode, UID: uid, GID: gid, NLink: nlink, Size: size}
	if !exists {
		if modifiedText != "" || changedText != "" {
			return FileIdentity{}, errors.New("missing identity contains timestamps")
		}
		return identity, nil
	}
	identity.ModifiedAt, err = parseStoreTime(modifiedText)
	if err != nil {
		return FileIdentity{}, err
	}
	identity.ChangedAt, err = parseStoreTime(changedText)
	if err != nil {
		return FileIdentity{}, err
	}
	return identity, nil
}

func validateJournal(journal Journal) error {
	if !validTransactionID(journal.TransactionID) || !validJournalPhase(journal.Phase) {
		return errors.New("journal identity or phase is invalid")
	}
	if err := validateCanonicalStorePath(journal.WorkingDirectory); err != nil {
		return errors.New("journal working directory is invalid")
	}
	if err := validateCanonicalStorePath(journal.ConfigurationPath); err != nil {
		return errors.New("journal configuration path is invalid")
	}
	if err := validateStoreTime(journal.CreatedAt); err != nil {
		return errors.New("journal creation time is invalid")
	}
	if len(journal.Files) == 0 || len(journal.Files) > maximumEditFiles {
		return errors.New("journal file count is invalid")
	}
	paths := make(map[string]struct{}, len(journal.Files))
	stages := make(map[string]struct{}, len(journal.Files))
	configurationCount := 0
	for index, file := range journal.Files {
		if file.Ordinal != index || file.Role != RoleConfiguration && file.Role != RoleDotenv {
			return errors.New("journal file order or role is invalid")
		}
		if file.Role == RoleConfiguration {
			configurationCount++
			if file.TargetPath != journal.ConfigurationPath {
				return errors.New("journal configuration path changed")
			}
		}
		if err := validateCanonicalStorePath(file.TargetPath); err != nil || filepath.Dir(file.TargetPath) != file.ParentPath {
			return errors.New("journal target path is invalid")
		}
		if filepath.Base(file.StageBasename) != file.StageBasename ||
			!strings.HasPrefix(file.StageBasename, ".acmemux-edit-"+journal.TransactionID+"-") {
			return errors.New("journal staging name is invalid")
		}
		if _, exists := paths[file.TargetPath]; exists {
			return errors.New("journal target path is duplicated")
		}
		paths[file.TargetPath] = struct{}{}
		stagePath := filepath.Join(file.ParentPath, file.StageBasename)
		if _, exists := stages[stagePath]; exists {
			return errors.New("journal staging path is duplicated")
		}
		stages[stagePath] = struct{}{}
		if !file.Parent.Exists || file.Parent.Device == 0 || file.Parent.Inode == 0 {
			return errors.New("journal parent identity is invalid")
		}
		if file.Original.Exists && !validOriginalIdentity(file.Original) {
			return errors.New("journal original identity is invalid")
		}
		if !file.Original.Exists && !zeroMissingIdentity(file.Original) {
			return errors.New("journal missing identity is invalid")
		}
		if file.CandidateReady != file.Candidate.Exists || file.CandidateReady && !validCandidateIdentity(file.Candidate) {
			return errors.New("journal candidate identity is invalid")
		}
		if !file.CandidateReady && !zeroMissingIdentity(file.Candidate) || file.Applied && !file.CandidateReady {
			return errors.New("journal candidate state is invalid")
		}
	}
	if configurationCount > 1 {
		return errors.New("journal contains multiple configuration targets")
	}
	return nil
}

func validOriginalIdentity(identity FileIdentity) bool {
	return identity.Exists && identity.Device != 0 && identity.Inode != 0 && identity.NLink == 1 &&
		identity.Size >= 0 && !identity.ModifiedAt.IsZero() && !identity.ChangedAt.IsZero()
}

func validCandidateIdentity(identity FileIdentity) bool {
	return identity.Exists && identity.Device != 0 && identity.Inode != 0 && identity.NLink == 1 &&
		identity.Size >= 0 && identity.Mode&syscall.S_IFMT == syscall.S_IFREG && identity.Mode&0o7777 == 0o600 &&
		identity.UID == uint32(os.Geteuid()) && !identity.ModifiedAt.IsZero() && !identity.ChangedAt.IsZero()
}

func zeroMissingIdentity(identity FileIdentity) bool {
	return !identity.Exists && identity.Device == 0 && identity.Inode == 0 && identity.Mode == 0 &&
		identity.UID == 0 && identity.GID == 0 && identity.NLink == 0 && identity.Size == 0 &&
		identity.ModifiedAt.IsZero() && identity.ChangedAt.IsZero()
}

func validTransactionID(value string) bool {
	if len(value) != 32 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

func validJournalPhase(phase JournalPhase) bool { return journalPhaseOrder(phase) >= 0 }

func journalPhaseOrder(phase JournalPhase) int {
	switch phase {
	case JournalStaging:
		return 0
	case JournalPrepared:
		return 1
	case JournalReplacing:
		return 2
	case JournalFinalizing:
		return 3
	default:
		return -1
	}
}

func formatOptionalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return formatStoreTime(value)
}

const insertJournalFileSQL = `INSERT INTO workspace_edit_journal_file (
journal_id, file_ordinal, role, target_path, parent_path, stage_basename,
target_existed, parent_device_decimal, parent_inode_decimal,
original_device_decimal, original_inode_decimal, original_mode, original_uid,
original_gid, original_nlink_decimal, original_size_bytes,
original_modified_at_utc, original_changed_at_utc
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

const loadJournalFilesSQL = `SELECT file_ordinal, role, target_path, parent_path,
stage_basename, target_existed, parent_device_decimal, parent_inode_decimal,
original_device_decimal, original_inode_decimal, original_mode, original_uid,
original_gid, original_nlink_decimal, original_size_bytes,
original_modified_at_utc, original_changed_at_utc,
candidate_ready, candidate_device_decimal, candidate_inode_decimal,
candidate_mode, candidate_uid, candidate_gid, candidate_nlink_decimal,
candidate_size_bytes, candidate_modified_at_utc, candidate_changed_at_utc, applied
FROM workspace_edit_journal_file WHERE journal_id = ? ORDER BY file_ordinal`
