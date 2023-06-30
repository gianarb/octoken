package octoken_test

import (
	"fmt"
	"testing"

	"go.gianarb.it/octoken"
)

func TestTokenGenerator(t *testing.T) {
	tg := octoken.NewTokenGenerator(6)
	token, err := tg.Generate("atp")
	if err != nil {
		t.Fatal(err)
	}
	if !tg.ValidateChecksum(token) {
		t.Fatal("should be valid")
	}
}

func ExampleNewTokenGenerator() {
	tg := octoken.NewTokenGenerator(6)
	token, err := tg.Generate("atp")
	if err != nil {
	}
	if !tg.ValidateChecksum(token) {
	}
}

func ExampleWithGenerateTokenFn() {
	tg := octoken.NewTokenGenerator(6, octoken.WithGenerateTokenFn(func() (string, error) {
		return "1234567", nil
	}))
	token, err := tg.Generate("atp")
	if err != nil {
		panic(err)
	}
	fmt.Println(token)
	// Output: atp_12345671sQzNR
}
