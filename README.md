# Blot

**Blot** is a variation of [Ben Laurie's
objecthash](https://github.com/benlaurie/objecthash) written in Rust combined
with [Multihash](https://github.com/multiformats/multihash).

Licensed under MIT (See [LICENSE](./LICENSE)).

## TODO

* specialise Value over Multihash? This should help enforce consistency with
  redacted values.
* bloton! (akin to js!)
* serde_json + schema (or Set flag) -> blot Value
* CLI


## Sketch

Hash a json blob:

```
$ blot -a sha2256 '["foo", "bar"]'
122032ae896c413cfdc79eec68be9139c86ded8b279238467c216cf2bec4d5f1e4a2
```

Hash a json blob where all arrays are sets:

```
$ blot -a sha2256 --list=set '["foo", "bar"]'
12201d572df95be4d038068133b6a162cbe2172f15bc7d8a020faca7a9a93e8a2649
```

```
$ blot -a sha2256 --list=set '["foo", "bar", "foo"]'
12201d572df95be4d038068133b6a162cbe2172f15bc7d8a020faca7a9a93e8a2649
```

```
$ blot -a sha2256 --list=list '["foo", "bar", "foo"]'
122026965c7662c672319dfd88cf23c55932633c9d175f4f0e7a3b2fa5bf789fe82b
```


### Blot Notation

```
// comment
1                    // Integer
1.0                  // Float
"foo"                // String
["foo"]              // List
["foo", 1]           // List
{"foo", "bar"}       // Set
{"foo": 1}           // Dict
0x1220fff000         // Raw
2018-10-11T12:13:14Z // Timestamp

{
  "foo": [1, 2, 3],
  "bar": {1, 2, 3},
  "qux": {"a": 0x1220fff000, "b": 1.0},
  "baz": {2018-01-01T00:00:00Z,2018-01-01T00:00:01Z, "bar"}
}
```
