An optional URL query string formatted set of options for how to serialize ABI decoded data into JSON.

### Defaults

By default when no options are specified, the following set of options are used

```
mode=object&number=string&bytes=hex&address=hex
```

### Mode

The following `mode` options can be used for the overall structure of the JSON returned:

- `object` (default) - the top-level JSON and all `tuples` fields (Solidity `struct`) will be JSON objects
    - The key will be the `name` as defined in the ABI
    -  If no `name` is provided for a field in the ABI, then the numeric index `0`,`1`,`2` etc. will be used
- `array` - the top-level JSON and all `tuple` fields will be JSON arrays
- `self-describing`  - each level is an array that contains the following fields
    - `name` - the name of the field from the ABI
    - `type` - the type of the field from the ABI, with a falst signature format for `tuple` children
    - `value` - the value of the field, which will be a self-describing sub-array in the case of `tuple` types

### Number

The following `number` options can be used for formatting of numbers - `uint256`, `int64` etc types:

- `string` (default) - a decimal (base-10) formatted string
- `hex` or`hex-0x` - a hexidecimal (base-16) formatted string prefixed with `0x`
- `number` - a JSON number of arbitrary precision
    - _Be careful if using this option_ that your JSON parsing library has been configured to support big integers
    - Ethereum token balances regularly use 18 decimals, meaning 100 would be `{"value": 100000000000000000000}`
    - Many default implementations of JSON parsing fail in obscure ways when parsing large numbers like this

### Bytes

The following `bytes` options can be used for formatting of byte types - `bytes`, `bytes32`.

- `hex` or`hex-0x` (default) - a hexidecimal (base-16) formatted string prefixed with `0x`
- `hex-plain` - a hexidecimal (base-16) formatted string with no prefix
- `base64` - a base64 (standard encoding) formatted string

### Address

The following `bytes` options can be used for formatting `address` type fields.

- `hex` or`hex-0x` (default) - a hexidecimal (base-16) formatted string prefixed with `0x`
- `hex-plain` - a hexidecimal (base-16) formatted string with no prefix
- `checksum` - ERC-55 mixed-case checksum address encoding

### Pretty

Setting `pretty`, or `pretty=true` in the query string will cause pretty printing of the returned JSON over multiple lines.

### Examples

Given this ABI we illustrate how different options will be formatted

```js
[
    {
        "name": "date",              // sample value:
        "type": "uint64"             //  1729450200
    },
    {
        "name": "stock",
        "type": "tuple[]",
        "components": [
            {
                "name": "item",       // sample value: 
                "type": "bytes32"     //  0xbb36636e2b58f2ca2538a966b95a253ed78c6bd1d176255be5a58c7ced3c21ea
            },
            {
                "name": "description", // sample value:
                "type": "string"       //  "widgetA"
            },
            {
                "name": "count",       // sample value:
                "type": "uint256"      //  100
            },
            {
                "name": "valueDiff",   // large negative sample value:
                "type": "int256"       //  -123456789012345678901234567890
            },
            {
                "name": "supplier",    // sample address
                "type": "address"      //   0xb8f7764d413b518c49824fb5e6078b41b2549d4e
            }
        ]
    }
]
```

#### Default (`mode=object&number=string&bytes=hex&address=hex`)

```js
{
    "date": "1729450200",
    "stock": [
        {
            "count": "100",
            "description": "widgetA",
            "valueDiff": "-123456789012345678901234567890",
            "item": "0xbb36636e2b58f2ca2538a966b95a253ed78c6bd1d176255be5a58c7ced3c21ea",
            "supplier": "0xb8f7764d413b518c49824fb5e6078b41b2549d4e"
        }
    ]
}
```

#### `mode=object&number=hex&bytes=hex-plain&address=checksum`

Note the numbers are all in hex, and the address is checksummed:

```js
{
    "date": "0x671550d8",
    "stock": [
        {
            "count": "0x64",
            "description": "widgetA",
            "valueDiff": "-0x18ee90ff6c373e0ee4e3f0ad2",
            "item": "bb36636e2b58f2ca2538a966b95a253ed78c6bd1d176255be5a58c7ced3c21ea",
            "supplier": "0xB8F7764d413B518c49824fb5E6078b41B2549d4e"
        }
    ]
}
```

#### `mode=object&number=json-number&bytes=base64&address=hex-plain`

Note the numbers are plain JSON numbers _including the one larger than a uint64 can hold_,
the bytes are Base64, but the address is still hex (with no prefix).

```js
{
    "date": 1729450200,
    "stock": [
        {
            "count": 100,
            "description": "widgetA",
            "valueDiff": -123456789012345678901234567890,
            "item": "uzZjbitY8solOKlmuVolPteMa9HRdiVb5aWMfO08Ieo=",
            "supplier": "b8f7764d413b518c49824fb5e6078b41b2549d4e"
        }
    ]
}
```

#### `mode=array&number=string&bytes=hex-plain&address=hex`

We've switched here to array formatting, including for the nested object.

> The order is very important now, as you must refer to the fields in ABI order to get the correct values.

```js
[
    "1729450200",
    [
        [
            "bb36636e2b58f2ca2538a966b95a253ed78c6bd1d176255be5a58c7ced3c21ea",
            "widgetA",
            "100",
            "-123456789012345678901234567890",
            "0xb8f7764d413b518c49824fb5e6078b41b2549d4e"
        ]
    ]
]
```

#### `mode=self-describing&number=json-number&bytes=hex`

This is the most complex format, where arrays are used that self-describe the data.

You still have formatting options on the leaf values, here using JSON numbers.

```js
[
    {
        "name": "date",
        "type": "uint64",
        "value": 1729450200
    },
    {
        "name": "stock",
        "type": "(bytes32,string,uint256,int256,address)[]",
        "value": [
            [
                {
                    "name": "item",
                    "type": "bytes32",
                    "value": "0xbb36636e2b58f2ca2538a966b95a253ed78c6bd1d176255be5a58c7ced3c21ea"
                },
                {
                    "name": "description",
                    "type": "string",
                    "value": "widgetA"
                },
                {
                    "name": "count",
                    "type": "uint256",
                    "value": 100
                },
                {
                    "name": "valueDiff",
                    "type": "int256",
                    "value": -123456789012345678901234567890
                },
                {
                    "name": "supplier",
                    "type": "address",
                    "value": "0xb8f7764d413b518c49824fb5e6078b41b2549d4e"
                }
            ]
        ]
    }
]
```