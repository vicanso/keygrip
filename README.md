# keygrip

[![Build Status](https://github.com/vicanso/keygrip/workflows/Test/badge.svg)](https://github.com/vicanso/keygrip/actions)

Keygrip is a module for signing and verifying data (such as cookies or URLs) through a rotating credential system, in which new server keys can be added and old ones removed regularly, without invalidating client credentials. It derives from [crypto-utils/keygrip](https://github.com/crypto-utils/keygrip).

Signatures use **HMAC-SHA256** and are encoded with `base64.RawURLEncoding`.

## API

#### kg := keygrip.New(keyList []string)

```go
kg := keygrip.New([]string{
    "key1",
    "key2",
})
```

For concurrent use (e.g. rotating keys while signing), create with `NewRWMutex`:

```go
kg := keygrip.NewRWMutex([]string{
    "key1",
    "key2",
})
```

#### Sign(data []byte)

Get the base64 digest (`RawURLEncoding`) using the first key in the key list.

```go
kg := keygrip.New([]string{
    "key1",
    "key2",
})
str := kg.Sign([]byte("tree.xie"))
// lOvR3UDUZm9jkNUsvtOyCnnxVkCn3QOaElodqz54_A8
fmt.Println(string(str))
```

#### Verify(data, digest []byte)

Loops through all keys until the digest matches. Returns `false` if none match or the digest is not valid encoding.

```go
kg := keygrip.New([]string{
    "key1",
    "key2",
})
fmt.Println(kg.Verify([]byte("tree.xie"), []byte("lOvR3UDUZm9jkNUsvtOyCnnxVkCn3QOaElodqz54_A8")))
// true
```

#### Index(data, digest []byte)

Returns the index of the matching key, `-1` if no key matches, or `-2` if the digest is not valid `base64.RawURLEncoding`.

```go
kg := keygrip.New([]string{
    "key1",
    "key2",
})
fmt.Println(kg.Index([]byte("tree.xie"), []byte("lOvR3UDUZm9jkNUsvtOyCnnxVkCn3QOaElodqz54_A8")))
// 0
```

#### AddKey(key string)

Adds a key to the **front** of the list (preferred for new signatures). Existing keys still verify until removed.

```go
kg := keygrip.New([]string{
    "key1",
    "key2",
})
kg.AddKey("key3")
```

#### RemoveKey(key string)

Removes a key from the list. Missing keys are ignored.
The **last remaining key is never removed** (no-op), so `Sign` always has a credential.

```go
kg := keygrip.New([]string{
    "key1",
    "key2",
})
kg.RemoveKey("key1")
```

#### SetKeys(keys []string)

Replaces the entire key list. `keys` must not be empty (panics if empty).

```go
kg.SetKeys([]string{"new-key-1", "new-key-2"})
```

#### Keys()

Returns a copy of the current key list.

```go
kg := keygrip.New([]string{
    "key1",
    "key2",
})
kg.Keys()
```

## test

```bash
make test-cover
```

### bench

```bash
make bench
```
