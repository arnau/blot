# Blot

**Blot** is a command-line interface (CLI) to compute hashes similar to tools
like `shasum` but using a variation of [Ben Laurie's
objecthash](https://github.com/benlaurie/objecthash) combined with
[Multihash](https://github.com/multiformats/multihash).

[![Build Status](https://www.travis-ci.org/arnau/blot.svg?branch=master)](https://www.travis-ci.org/arnau/blot)

Licensed under MIT (See [LICENSE](./LICENSE)).


## Usage

Compact output:

```
$ blot -a sha2-256 '["foo", "bar"]'
```

<pre style="background-color: #000; font-family: monospace; color: #fff">
<span style="background-color: #ff0087">12</span><span style="background-color: #00afff">20</span><span style="color: #ffd75f">32ae896c413cfdc79eec68be9139c86ded8b279238467c216cf2bec4d5f1e4a2</span>
</pre>

Verbose output:

```
$ blot -a blake2b-512 --verbose '"foo"'
```

<pre style="background-color: #000; font-family: monospace; color: #fff">
<span style="background-color: #ff0087">Codec: </span> 0xb240 (blake2b-512)
<span style="background-color: #00afff">Length:</span> 0x40
<span style="background-color: #ffd75f">Digest:</span> 0x20fb5053ecefc742b73665625613de5ea09917988fac07d2977ece1c9bebb1aa0e5dfe8e3f2ae7b30ac3b97fac511a4745d71f5d4dbb211d69d06b34fb031e60
</pre>


## See also

* [blot library](blot-lib)

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
