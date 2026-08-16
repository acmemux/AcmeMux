package configuration

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"strconv"
	"time"

	"github.com/sgurden-certleap/AcmeMux/internal/integrations"
	"github.com/sgurden-certleap/AcmeMux/internal/nativeconfig"
	"github.com/sgurden-certleap/AcmeMux/internal/workspace"
)

const reviewTokenBytes = sha256.Size

type tokenWriter struct {
	mac hashWriter
}

type hashWriter interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}

func newTokenWriter(key []byte, domain string) *tokenWriter {
	writer := &tokenWriter{mac: hmac.New(sha256.New, key)}
	writer.text(domain)
	return writer
}

func (writer *tokenWriter) bytes(value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.mac.Write(length[:])
	_, _ = writer.mac.Write(value)
}

func (writer *tokenWriter) text(value string) { writer.bytes([]byte(value)) }

func (writer *tokenWriter) integer(value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	writer.bytes(encoded[:])
}

func (writer *tokenWriter) boolean(value bool) {
	if value {
		writer.integer(1)
		return
	}
	writer.integer(0)
}

func (writer *tokenWriter) token() string {
	return base64.RawURLEncoding.EncodeToString(writer.mac.Sum(nil))
}

func (service *Service) sourceToken(runtime runtimeContext, sources *workspace.SourceSet) string {
	writer := newTokenWriter(service.tokenKey, "acmemux-native-source-v1")
	writer.text(string(runtime.manifestID))
	writer.text(runtime.fingerprint)
	writer.text(workspace.ReviewFingerprint(sources.Selection.Review))
	files := sources.Files()
	writer.integer(uint64(len(files)))
	for _, file := range files {
		writeSourceFingerprint(writer, file)
	}
	return writer.token()
}

func writeSourceFingerprint(writer *tokenWriter, file workspace.SourceFile) {
	writer.text(string(file.Role))
	writer.text(file.Path)
	writer.text(file.Reference)
	identity := file.Fingerprint.Identity
	writer.boolean(identity.Exists)
	writer.integer(identity.Device)
	writer.integer(identity.Inode)
	writer.integer(uint64(identity.Mode))
	writer.integer(uint64(identity.UID))
	writer.integer(uint64(identity.GID))
	writer.integer(identity.NLink)
	writer.text(strconv.FormatInt(identity.Size, 10))
	writer.text(canonicalTime(identity.ModifiedAt))
	writer.text(canonicalTime(identity.ChangedAt))
	writer.bytes(file.Fingerprint.SHA256[:])
}

func canonicalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func (service *Service) recoveryToken(runtimeFingerprint string, recovery workspace.Recovery) string {
	writer := newTokenWriter(service.tokenKey, "acmemux-native-recovery-v1")
	writer.text(runtimeFingerprint)
	writer.text(recovery.TransactionID)
	writer.text(recovery.WorkingDirectory)
	writer.text(recovery.ConfigurationPath)
	writer.text(string(recovery.Phase))
	writer.text(string(recovery.State))
	writer.integer(uint64(len(recovery.Files)))
	for _, file := range recovery.Files {
		writer.integer(uint64(file.Ordinal))
		writer.text(string(file.Role))
		writer.text(file.Path)
		writer.text(string(file.State))
	}
	return writer.token()
}

func (service *Service) previewToken(baseToken string, changes []nativeconfig.Change, candidate []byte, replacements []workspace.Replacement) string {
	writer := newTokenWriter(service.tokenKey, "acmemux-native-preview-v1")
	writer.text(baseToken)
	writer.integer(uint64(len(changes)))
	for _, change := range changes {
		writer.text(string(change.FieldID))
		writer.text(string(change.Operation))
		writer.integer(uint64(len(change.Bindings)))
		for _, binding := range change.Bindings {
			writer.text(string(binding.ID))
			writer.text(binding.Value)
		}
		writeIntegrationValue(writer, change.Value)
	}
	writer.bytes(candidate)
	writer.integer(uint64(len(replacements)))
	for _, replacement := range replacements {
		writer.text(string(replacement.Role))
		writer.text(replacement.Path)
		writer.bytes(replacement.Content)
	}
	return writer.token()
}

func writeIntegrationValue(writer *tokenWriter, value integrations.Value) {
	writer.text(string(value.Kind()))
	switch value.Kind() {
	case integrations.FieldString:
		text, _ := value.String()
		writer.text(text)
	case integrations.FieldBoolean:
		boolean, _ := value.Boolean()
		writer.boolean(boolean)
	case integrations.FieldInteger:
		integer, _ := value.Integer()
		writer.text(strconv.FormatInt(integer, 10))
	case integrations.FieldStringList:
		values, _ := value.StringList()
		writer.integer(uint64(len(values)))
		for _, item := range values {
			writer.text(item)
		}
	}
}

func tokenMatches(expected, supplied string) bool {
	if len(supplied) != 43 {
		return false
	}
	expectedBytes, expectedErr := base64.RawURLEncoding.DecodeString(expected)
	suppliedBytes, suppliedErr := base64.RawURLEncoding.DecodeString(supplied)
	if expectedErr != nil || suppliedErr != nil || len(expectedBytes) != reviewTokenBytes || len(suppliedBytes) != reviewTokenBytes {
		return false
	}
	return subtle.ConstantTimeCompare(expectedBytes, suppliedBytes) == 1
}
