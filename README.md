octoken is a Go library written to generate and validate authentication token.

```go
package main

import (
	"go.gianarb.it/octoken"
)

func main() {
    tg := octoken.NewTokenGenerator()

    // generate a new token
    token, err := tg.Generate("atp")
    if err != nil {
        panic(err)
    }

    // ideally here you should store it somewhere to make future validation
    // when a user or an application will use it

    // this function validates that the checksum and the token are aligned.
    // if they are not you don't even need to look further, the token is invalid.
    if !tg.ValidateChecksum(token) {
        panic("checksum and not do not align. Invalid token")
    }
}
```

## Why

I wrote this library because token generation is a common problem I had to
solve continuously for every project I develop.

## Inspired by GitHub

I like to learn and reuse cool solutions. I tend to avoid custom solution when
I can because there are a lot of smart people studying and sharing their
solution, very often I can't come up with something better on my own.

I think token generation is one of those.

A few years ago I read ["Behind GitHub’s new authentication token
formats"](https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/)
from the GitHub technical blog, we implemented a similar solution in a project
and it is working since then.

Recently I had the same problem again in a different project and I decided to
write this solution as standalone library.

## Documentation

Have a look at godocs for this library where you can find the API documentation and a few examples.
