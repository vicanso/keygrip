# keygrip

[![Build Status](https://img.shields.io/travis/vicanso/keygrip.svg?label=linux+build)](https://travis-ci.org/vicanso/keygrip)

Keygrip is a module for signing and verifying data (such as cookies or URLs) through a rotating credential system, in which new server keys can be added and old ones removed regularly, without invalidating client credentials. It derives from [crypto-utils/keygrip](https://github.com/crypto-utils/keygrip).

## API

#### kg := keygrip.New(keyList []string)

```go
kg := keygrip.New([]string{
    "key1",
    "key2",
})
```

#### Sign(data []byte)

Get the base64 digest(RawURLEncoding) on the first key in the keylist.

```go
kg := keygrip.New([]string{
    "key1",
    "key2",
})
str := kg.Sign([]byte("tree.xie"))
// VOauNTAF3i24kD9EN5foGvhXNnI
fmt.Println(string(str))
```

#### Verify(data, digest []byte)

This loops through all of the keys currently in the keylist until the digest of the current key matches the given digest. Otherwise it will return false.


```go
kg := keygrip.New([]string{
    "key1",
    "key2",
})
fmt.Println(kg.Verify([]byte("tree.xie"), []byte( "VOauNTAF3i24kD9EN5foGvhXNnI")))
```

#### Index(data, digest []byte)

This loops through all of the keys currently in the keylist until the digest of the current key matches the given digest, at which point the current index is returned. If no key is matched, -1 is returned.


```go
kg := keygrip.New([]string{
    "key1",
    "key2",
})
fmt.Println(kg.Index([]byte("tree.xie"), []byte("VOauNTAF3i24kD9EN5foGvhXNnI")))
```

#### AddKey(key string)

Add key to the front of key list

```go
kg := keygrip.New([]string{
    "key1",
    "key2",
})
kg.Add("key3")
```

#### RemoveKey(key string)

Remove key from key list

```go
kg := keygrip.New([]string{
    "key1",
    "key2",
})
kg.Remove("key1")
```

#### Keys()

Get the key list

```go
kg := keygrip.New([]string{
    "key1",
    "key2",
})
kg.Keys()
```

#### RemoveAllKeys()

Remove all keys

```go
kg := keygrip.New([]string{
    "key1",
    "key2",
})
kg.RemoveAllKeys()
```

## test

make test-cover

### bench

make bench
