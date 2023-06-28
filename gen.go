package octoken

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"math/big"
	"strings"
)

var ErrGenerateToken error

type GenerateTokenFn func() (string, error)

func NewTokenGenerator(m int, gfn GenerateTokenFn) *TokenGenerator {
	return &TokenGenerator{
		maxChecksumLen:  m,
		generateTokenFn: gfn,
	}
}

type TokenGenerator struct {
	maxChecksumLen  int
	generateTokenFn GenerateTokenFn
}

// GenerateSecureToken is the default function provieded by octoken to generate
// the random part of the token.  You have to specify how long you want such
// section to be.
// Thanks Andzej Maciusovic https://stackoverflow.com/a/59457748
func GenerateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b)[0:length], nil
}

func (t *TokenGenerator) Generate(prefix string) (string, error) {
	token, err := t.generateTokenFn()
	if err != nil {
		return "", fmt.Errorf(err.Error(), ErrGenerateToken)
	}
	cc := crc32.ChecksumIEEE([]byte(token))
	checksum := toBase62(cc)
	if len(checksum) > t.maxChecksumLen {
		return "", errors.New("checksum too long, passed token is too long")
	}

	return fmt.Sprintf(
		"%s_%s%s%s",
		prefix,
		token,
		strings.Repeat("0", t.maxChecksumLen-len(checksum)),
		checksum), nil
}
func (t *TokenGenerator) ValidateChecksum(token string) bool {
	encoded := token[len(token)-6:]
	decoded := token[4 : len(token)-6]
	cc := crc32.ChecksumIEEE([]byte(decoded))
	checksum := toBase62(cc)
	if encoded == fmt.Sprintf("%s%s", strings.Repeat("0", t.maxChecksumLen-len(checksum)), checksum) {
		return true
	}

	return false
}

func toBase62(token uint32) string {
	var i big.Int
	i.SetUint64(uint64(token))
	return i.Text(62)
}

func parseBase62(s string) ([]byte, error) {
	var i big.Int
	_, ok := i.SetString(s, 62)
	if !ok {
		return nil, fmt.Errorf("cannot parse base62: %q", s)
	}

	return i.Bytes(), nil
}
