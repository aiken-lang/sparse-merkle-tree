# sparse-merkle-tree

***WIP Have a few more kinks to iron out***

The merkle tree functions are located in sparse.ak. 

Currently the supported functionality is:
- Verifying a new root with an added member.
- Verifying a new root with a removed member.
- Verifying a member is included in the tree.
- Verifying a member is not included in the tree. 

## Building

```sh
aiken build
```

## Testing

Tests are located in sparse_test.ak



## Offchain code
Since the onchain code requires a very specific implementation of the sparse merkle tree,
I have added an implementation of the offchain code in rust. 
This implementation was forked from https://github.com/nervosnetwork/sparse-merkle-tree/tree/master
and then modified to work with the on chain code.

The only thing remaining for the offchain code is to support other storage types like on disk or remote storage.
If you want to contribute to further improving the offchain reach out to any of the Aiken core maintainers.


## Documentation

If you're writing a library, you might want to generate an HTML documentation for it.

Use:

```sh
aiken docs
```

## Resources

Find more on the [Aiken's user manual](https://aiken-lang.org).
