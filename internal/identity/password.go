package identity

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	minimumPasswordRunes = 12
	maximumPasswordBytes = 1024
	maximumVerifierBytes = 1024

	minimumAcceptedMemory      = 8 * 1024
	maximumAcceptedMemory      = 256 * 1024
	minimumAcceptedIterations  = 1
	maximumAcceptedIterations  = 10
	minimumAcceptedParallelism = 1
	maximumAcceptedParallelism = 16
	minimumAcceptedSaltLength  = 16
	maximumAcceptedSaltLength  = 64
	minimumAcceptedKeyLength   = 16
	maximumAcceptedKeyLength   = 64
)

type parsedVerifier struct {
	parameters passwordParameters
	salt       []byte
	hash       []byte
}

func validateNewPassword(password []byte) error {
	if len(password) > maximumPasswordBytes || !utf8.Valid(password) || utf8.RuneCount(password) < minimumPasswordRunes {
		return ErrPasswordRejected
	}
	return nil
}

func validatePasswordParameters(parameters passwordParameters) error {
	if parameters.memory < minimumAcceptedMemory || parameters.memory > maximumAcceptedMemory {
		return errors.New("Argon2id memory is outside supported bounds")
	}
	if parameters.iterations < minimumAcceptedIterations || parameters.iterations > maximumAcceptedIterations {
		return errors.New("Argon2id iterations are outside supported bounds")
	}
	if parameters.parallelism < minimumAcceptedParallelism || parameters.parallelism > maximumAcceptedParallelism {
		return errors.New("Argon2id parallelism is outside supported bounds")
	}
	if parameters.saltLength < minimumAcceptedSaltLength || parameters.saltLength > maximumAcceptedSaltLength {
		return errors.New("Argon2id salt length is outside supported bounds")
	}
	if parameters.keyLength < minimumAcceptedKeyLength || parameters.keyLength > maximumAcceptedKeyLength {
		return errors.New("Argon2id key length is outside supported bounds")
	}
	return nil
}

func (service *Service) encodePassword(ctx context.Context, password []byte) (string, error) {
	parameters := service.passwordParameters
	salt := make([]byte, parameters.saltLength)
	if err := service.readRandom(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	hash, err := service.derivePassword(ctx, password, salt, parameters)
	if err != nil {
		return "", err
	}
	return formatVerifier(parameters, salt, hash), nil
}

func formatVerifier(parameters passwordParameters, salt, hash []byte) string {
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		parameters.memory,
		parameters.iterations,
		parameters.parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

func (service *Service) verifyPassword(ctx context.Context, password []byte, encoded string) (bool, parsedVerifier, error) {
	verifier, err := parseVerifier(encoded)
	if err != nil {
		return false, parsedVerifier{}, err
	}
	actual, err := service.derivePassword(ctx, password, verifier.salt, verifier.parameters)
	if err != nil {
		return false, parsedVerifier{}, err
	}
	return subtle.ConstantTimeCompare(actual, verifier.hash) == 1, verifier, nil
}

func (service *Service) derivePassword(ctx context.Context, password, salt []byte, parameters passwordParameters) ([]byte, error) {
	select {
	case service.kdfSlots <- struct{}{}:
		defer func() { <-service.kdfSlots }()
	case <-ctx.Done():
		return nil, fmt.Errorf("wait for password verifier capacity: %w", ctx.Err())
	}

	return argon2.IDKey(
		password,
		salt,
		parameters.iterations,
		parameters.memory,
		parameters.parallelism,
		parameters.keyLength,
	), nil
}

func parseVerifier(encoded string) (parsedVerifier, error) {
	if len(encoded) == 0 || len(encoded) > maximumVerifierBytes {
		return parsedVerifier{}, ErrVerifierUnsupported
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return parsedVerifier{}, ErrVerifierUnsupported
	}

	parameterParts := strings.Split(parts[3], ",")
	if len(parameterParts) != 3 {
		return parsedVerifier{}, ErrVerifierUnsupported
	}
	memory, err := parsePHCInteger(parameterParts[0], "m=", 32)
	if err != nil {
		return parsedVerifier{}, ErrVerifierUnsupported
	}
	iterations, err := parsePHCInteger(parameterParts[1], "t=", 32)
	if err != nil {
		return parsedVerifier{}, ErrVerifierUnsupported
	}
	parallelism, err := parsePHCInteger(parameterParts[2], "p=", 8)
	if err != nil {
		return parsedVerifier{}, ErrVerifierUnsupported
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return parsedVerifier{}, ErrVerifierUnsupported
	}
	hash, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return parsedVerifier{}, ErrVerifierUnsupported
	}
	parameters := passwordParameters{
		memory:      uint32(memory),
		iterations:  uint32(iterations),
		parallelism: uint8(parallelism),
		saltLength:  uint32(len(salt)),
		keyLength:   uint32(len(hash)),
	}
	if err := validatePasswordParameters(parameters); err != nil {
		return parsedVerifier{}, ErrVerifierUnsupported
	}
	return parsedVerifier{parameters: parameters, salt: salt, hash: hash}, nil
}

func parsePHCInteger(value, prefix string, bits int) (uint64, error) {
	if !strings.HasPrefix(value, prefix) || len(value) == len(prefix) {
		return 0, ErrVerifierUnsupported
	}
	raw := strings.TrimPrefix(value, prefix)
	if raw[0] == '0' && len(raw) > 1 {
		return 0, ErrVerifierUnsupported
	}
	parsed, err := strconv.ParseUint(raw, 10, bits)
	if err != nil {
		return 0, ErrVerifierUnsupported
	}
	return parsed, nil
}

func shouldUpgradePassword(stored parsedVerifier, current passwordParameters) bool {
	storedParameters := stored.parameters
	noFactorWouldDecrease := storedParameters.memory <= current.memory &&
		storedParameters.iterations <= current.iterations &&
		storedParameters.parallelism <= current.parallelism &&
		storedParameters.saltLength <= current.saltLength &&
		storedParameters.keyLength <= current.keyLength
	if !noFactorWouldDecrease {
		return false
	}
	return storedParameters.memory < current.memory ||
		storedParameters.iterations < current.iterations ||
		storedParameters.parallelism < current.parallelism ||
		storedParameters.saltLength < current.saltLength ||
		storedParameters.keyLength < current.keyLength
}
