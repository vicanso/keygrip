# keygrip

Keygrip is a module for signing and verifying data (such as cookies or URLs) through a rotating credential system, in which new server keys can be added and old ones removed regularly, without invalidating client credentials. It derives from [crypto-utils/keygrip](https://github.com/crypto-utils/keygrip).

## API

### kg := keygrip.New(keyList []string)

```go
kg := keygrip.New([]string{
    "key1",
    "key2",
})
```

### Sign(data string)

```go
kg := keygrip.New([]string{
    "key1",
    "key2",
})
str := kg.Sign("tree.xie")
// VOauNTAF3i24kD9EN5foGvhXNnI
fmt.Println(str)
```

### Verify(data, digest string)

```go
kg := keygrip.New([]string{
    "key1",
    "key2",
})
fmt.Println(kg.Verify("tree.xie", "VOauNTAF3i24kD9EN5foGvhXNnI"))
```

### AddKey(key string)

Add key to the front of key list

```go
kg := keygrip.New([]string{
    "key1",
    "key2",
})
kg.Add("key3")
```

### RemoveKey(key string)

```go
kg := keygrip.New([]string{
    "key1",
    "key2",
})
kg.Remove("key1")
```

## test

go test -race -coverprofile=test.out ./... && go tool cover --html=test.out

### bench

go test -v -bench=".*" ./