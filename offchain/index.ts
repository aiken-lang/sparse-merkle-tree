import { blake2b } from "blakejs";
import { BitSet } from "bitSet";
import { Buffer } from "buffer";

const message = new TextEncoder().encode("apple (0)");
const leafBytes = new Uint8Array(Buffer.from("0deeffaad07783", "hex"));

export class Leaf {
  key: BitSet;
  value: Uint8Array;
  leafHash: Uint8Array;

  constructor(value: String | Buffer) {
    const bufferValue: Uint8Array =
      value instanceof String
        ? new TextEncoder().encode(value.toString())
        : new Uint8Array(value);

    this.key = new BitSet(blake2b(bufferValue, undefined, 32));

    this.value = bufferValue;

    this.leafHash = blake2b(
      Buffer.concat([leafBytes, blake2b(bufferValue, undefined, 32)]),
      undefined,
      32
    );
  }

  static boundaryLeaf(isMin: boolean) {
    if (isMin) {
      let x = new Leaf(Buffer.from("00", "hex"));

      x.key.clear(0, 256);

      x.leafHash = blake2b(
        Buffer.concat([leafBytes, new Uint8Array(32).fill(0)]),
        undefined,
        32
      );

      return x;
    } else {
      let x = new Leaf(Buffer.from("00", "hex"));

      x.key.setRange(0, 255, 1);

      x.leafHash = blake2b(
        Buffer.concat([leafBytes, new Uint8Array(32).fill(255)]),
        undefined,
        32
      );

      return x;
    }
  }
}

export class Branch {
  key: BitSet;
  branchHash: Uint8Array;
  leftChild: Leaf | Branch;
  rightChild: Leaf | Branch;
  height: number;

  constructor(leftChild: Leaf | Branch, rightChild: Leaf | Branch) {
    this.leftChild = leftChild;
    this.rightChild = rightChild;

    let leftKey = leftChild.key.clone();
    let rightKey = rightChild.key.clone();
    let currentHeight = -1;

    if (leftChild instanceof Leaf) {
      const heightDiff = rightChild instanceof Leaf ? 0 : rightChild.height + 1;

      leftKey = leftKey.slice(heightDiff);
    } else if (rightChild instanceof Leaf) {
      const heightDiff = leftChild instanceof Leaf ? 0 : leftChild.height + 1;

      rightKey = rightKey.slice(heightDiff);
    } else {
      currentHeight = Math.max(leftChild.height, rightChild.height);
      if (leftChild.height > rightChild.height) {
        leftKey = leftKey.slice(leftChild.height - rightChild.height);
      } else {
        rightKey = rightKey.slice(rightChild.height - leftChild.height);
      }
    }

    while (!leftKey.equals(rightKey)) {
      leftKey = leftKey.slice(1);
      rightKey = rightKey.slice(1);
      currentHeight++;

      console.log(leftKey.toString(), rightKey.toString(), currentHeight);
    }

    this.key = leftKey;
    this.height = currentHeight;

    if (leftChild instanceof Leaf) {
      this.branchHash = blake2b(
        Buffer.concat([
          leftChild.leafHash,
          new Uint8Array(1).fill(currentHeight),
          rightChild instanceof Leaf
            ? rightChild.leafHash
            : rightChild.branchHash,
        ]),
        undefined,
        32
      );
    } else {
      this.branchHash = blake2b(
        Buffer.concat([
          leftChild.branchHash,
          new Uint8Array(1).fill(currentHeight),
          rightChild instanceof Leaf
            ? rightChild.leafHash
            : rightChild.branchHash,
        ]),
        undefined,
        32
      );
    }
  }
}

export class SparseMerkleTree extends Branch {
  leaves: Map<Uint8Array, Leaf>;

  constructor() {
    const leftChild = Leaf.boundaryLeaf(true);
    const rightChild = Leaf.boundaryLeaf(false);
    super(leftChild, rightChild);
    this.leaves = new Map();
  }
}
