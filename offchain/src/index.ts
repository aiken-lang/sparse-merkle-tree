import { blake2b, blake2bHex } from "blakejs";
import { BitSet } from "bitSet";
import { Buffer } from "buffer";

const leafBytes = new Uint8Array(Buffer.from("0deeffaad07783", "hex"));

export class Leaf {
  key: BitSet;
  value: Uint8Array;
  leafHash: Uint8Array;

  constructor(value: string | Buffer) {
    const bufferValue: Uint8Array =
      typeof value == "string"
        ? new TextEncoder().encode(value)
        : new Uint8Array(value);

    this.key = new BitSet(blake2b(bufferValue, undefined, 32));

    this.value = bufferValue;

    this.leafHash = blake2b(
      Buffer.concat([leafBytes, blake2b(bufferValue, undefined, 32)]),
      undefined,
      32
    );
  }

  doInsert(key: BitSet, value: string | Buffer) {
    let other = new Leaf(value);

    let testBit = -1;

    while (!key.slice(testBit + 1).equals(this.key.slice(testBit + 1))) {
      testBit++;
    }

    if (testBit < 0) {
      throw new Error("Key already exists");
    }

    if (key.get(testBit) === 0 ? true : false) {
      const newBranch = new Branch(this, other);

      return newBranch;
    } else {
      const newBranch = new Branch(other, this);

      return newBranch;
    }
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

  constructor(childOne: Leaf | Branch, childTwo: Leaf | Branch) {
    let keyOne = childOne.key.clone();
    let keyTwo = childTwo.key.clone();
    let currentHeight = -1;

    if (childOne instanceof Leaf) {
      const heightDiff = childTwo instanceof Leaf ? 0 : childTwo.height + 1;

      keyOne = keyOne.slice(heightDiff);
    } else if (childTwo instanceof Leaf) {
      const heightDiff = childOne instanceof Leaf ? 0 : childOne.height + 1;

      keyTwo = keyTwo.slice(heightDiff);
    } else {
      currentHeight = Math.max(childOne.height, childTwo.height);
      if (childOne.height > childTwo.height) {
        keyOne = keyOne.slice(childOne.height - childTwo.height);
      } else {
        keyTwo = keyTwo.slice(childTwo.height - childOne.height);
      }
    }

    while (!keyOne.equals(keyTwo)) {
      keyOne = keyOne.slice(1);
      keyTwo = keyTwo.slice(1);
      currentHeight++;
    }

    this.key = keyOne;
    this.height = currentHeight;

    if (childOne.key.get(currentHeight) === 0 ? true : false) {
      this.leftChild = childOne;
      this.rightChild = childTwo;
    } else {
      this.leftChild = childTwo;
      this.rightChild = childOne;
    }

    if (this.leftChild instanceof Leaf) {
      this.branchHash = blake2b(
        Buffer.concat([
          this.leftChild.leafHash,
          new Uint8Array(1).fill(currentHeight),
          this.rightChild instanceof Leaf
            ? this.rightChild.leafHash
            : this.rightChild.branchHash,
        ]),
        undefined,
        32
      );
    } else {
      this.branchHash = blake2b(
        Buffer.concat([
          this.leftChild.branchHash,
          new Uint8Array(1).fill(currentHeight),
          this.rightChild instanceof Leaf
            ? this.rightChild.leafHash
            : this.rightChild.branchHash,
        ]),
        undefined,
        32
      );
    }
  }

  doInsert(key: BitSet, value: string | Buffer): Branch | Leaf {
    if (key.slice(this.height + 1).equals(this.key)) {
      let leftHeight = this.height - 1;

      if (this.leftChild instanceof Leaf) {
        while (leftHeight > -1) {
          if (
            key
              .slice(leftHeight + 1)
              .equals(this.leftChild.key.slice(leftHeight + 1))
          ) {
            break;
          }

          leftHeight--;
        }
      } else {
        while (leftHeight >= this.leftChild.height) {
          if (
            key
              .slice(leftHeight + 1)
              .equals(
                this.leftChild.key.slice(leftHeight - this.leftChild.height)
              )
          ) {
            break;
          }

          leftHeight--;
        }
        if (leftHeight < this.leftChild.height) {
          leftHeight = -1;
        }
      }

      let rightHeight = this.height - 1;

      if (this.rightChild instanceof Leaf) {
        while (rightHeight > -1) {
          if (
            key
              .slice(rightHeight + 1)
              .equals(this.rightChild.key.slice(rightHeight + 1))
          ) {
            break;
          }

          rightHeight--;
        }
      } else {
        while (rightHeight >= this.rightChild.height) {
          if (
            key
              .slice(rightHeight + 1)
              .equals(
                this.rightChild.key.slice(rightHeight - this.rightChild.height)
              )
          ) {
            break;
          }

          rightHeight--;
        }
        if (rightHeight < this.rightChild.height) {
          rightHeight = -1;
        }
      }

      if (leftHeight > 0 && rightHeight < 0) {
        this.leftChild = this.leftChild.doInsert(key, value);
      } else if (leftHeight < 0 && rightHeight > 0) {
        this.rightChild = this.rightChild.doInsert(key, value);
      } else {
        throw new Error("Impossible");
      }

      if (this.leftChild instanceof Leaf) {
        this.branchHash = blake2b(
          Buffer.concat([
            this.leftChild.leafHash,
            new Uint8Array(1).fill(this.height),
            this.rightChild instanceof Leaf
              ? this.rightChild.leafHash
              : this.rightChild.branchHash,
          ]),
          undefined,
          32
        );
      } else {
        this.branchHash = blake2b(
          Buffer.concat([
            this.leftChild.branchHash,
            new Uint8Array(1).fill(this.height),
            this.rightChild instanceof Leaf
              ? this.rightChild.leafHash
              : this.rightChild.branchHash,
          ]),
          undefined,
          32
        );
      }

      return this;
    } else {
      return new Branch(new Leaf(value), this);
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

  insert(value: string | Buffer) {
    const bufferValue: Uint8Array =
      typeof value == "string"
        ? new TextEncoder().encode(value)
        : new Uint8Array(value);

    const initialKey = new BitSet(blake2b(bufferValue, undefined, 32));

    super.doInsert(initialKey, value);
  }
}
