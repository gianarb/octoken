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

// Error used to notify when the function used to generate a token fails.
var ErrGenerateToken error

// GenerateTokenFn can be used to define the logic you want to use to generate
// the random part of the token
type GenerateTokenFn func() (string, error)

// Override the default function used to generate the random part of the token
func WithGenerateTokenFn(fn GenerateTokenFn) func(*TokenGenerator) {
	return func(s *TokenGenerator) {
		s.generateTokenFn = fn
	}
}

func WithTokenLength(l int) func(*TokenGenerator) {
	return func(s *TokenGenerator) {
		s.tokenLength = l
	}
}

func WithChecksumLength(l int) func(*TokenGenerator) {
	return func(s *TokenGenerator) {
		s.chekcsumLength = l
	}
}

// NewTokenGenerator is a function used to construct a TokenGenerator
// The first parameter identifies
func NewTokenGenerator(opt ...func(*TokenGenerator)) *TokenGenerator {
	tg := &TokenGenerator{
		chekcsumLength:  6,
		tokenLength:     30,
		generateTokenFn: func() (string, error) { return GenerateSecureToken(30) },
	}
	for _, o := range opt {
		o(tg)
	}
	return tg
}

type TokenGenerator struct {
	tokenLength     int
	chekcsumLength  int
	generateTokenFn GenerateTokenFn
}

// GenerateSecureToken is the default function provieded by octoken to generate
// the random part of the token.  You have to specify how long you want such
// section to be.
// Thanks Andzej Maciusovic https://stackoverflow.com/a/59457748
func GenerateSecureToken(lenght int) (string, error) {
	b := make([]byte, lenght)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b)[0:lenght], nil
}

func (t *TokenGenerator) Generate(prefix string) (string, error) {
	token, err := t.generateTokenFn()
	if err != nil {
		return "", fmt.Errorf(err.Error(), ErrGenerateToken)
	}
	cc := crc32.ChecksumIEEE([]byte(token))
	checksum := toBase62(cc)
	if len(checksum) > t.chekcsumLength {
		return "", errors.New("checksum too long, passed token is too long")
	}

	return fmt.Sprintf(
		"%s_%s%s%s",
		prefix,
		token,
		strings.Repeat("0", t.chekcsumLength-len(checksum)),
		checksum), nil
}
func (t *TokenGenerator) ValidateChecksum(full string) bool {
	parts := strings.Split(full, "_")
	token := parts[1]
	encoded := token[len(token)-t.chekcsumLength:]
	decoded := token[:len(token)-t.chekcsumLength]
	cc := crc32.ChecksumIEEE([]byte(decoded))
	checksum := toBase62(cc)
	if encoded == fmt.Sprintf("%s%s", strings.Repeat("0", t.chekcsumLength-len(checksum)), checksum) {
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
