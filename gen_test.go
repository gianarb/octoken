package octoken_test

import (
	"testing"

	"go.gianarb.it/octoken"
)

func TestTokenGenerator(t *testing.T) {
	tg := octoken.NewTokenGenerator(6, func() (string, error) {
		return octoken.GenerateSecureToken(30)
	})
	token, err := tg.Generate("atp")
	if err != nil {
		t.Fatal(err)
	}
	if !tg.ValidateChecksum(token) {
		t.Fatal("should be valid")
	}
}

func ExampleNewTokenGenerator() {
	tg := octoken.NewTokenGenerator(6, func() (string, error) {
		return octoken.GenerateSecureToken(30)
	})
	token, err := tg.Generate("atp")
	if err != nil {
	}
	if !tg.ValidateChecksum(token) {
	}
}
