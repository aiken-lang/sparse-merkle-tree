import { blake2b, blake2bHex } from "blakejs";
import { BitSet } from "bitSet";
import { Buffer } from "buffer";

const leafBytes = new Uint8Array(Buffer.from("0deeffaad07783", "hex"));

type Side = "left" | "right";

class MerkleProof {
  startingSide: Side | undefined;
  leftLeaf: Uint8Array | undefined;
  rightLeaf: Uint8Array | undefined;
  leftProofs: [Uint8Array, number][];
  rightProofs: [Uint8Array, number][];
  continuingSideProofs: [Uint8Array, number][];
  remainingProofs: [Uint8Array, number, Side][];
  leftRightHeight: number | undefined;
  intersectingHeight: number | undefined;

  constructor() {
    this.remainingProofs = [];
    this.leftProofs = [];
    this.rightProofs = [];
    this.continuingSideProofs = [];
  }

  insertRemainingProof(
    hash: Uint8Array,
    height: number,
    side: Side
  ): MerkleProof {
    this.remainingProofs.push([hash, height, side]);

    return this;
  }

  insertLeftProof(hash: Uint8Array, height: number): MerkleProof {
    this.leftProofs.push([hash, height]);

    return this;
  }

  insertRightProof(hash: Uint8Array, height: number): MerkleProof {
    this.rightProofs.push([hash, height]);

    return this;
  }

  insertContinuingSideProof(hash: Uint8Array, height: number): MerkleProof {
    this.continuingSideProofs.push([hash, height]);

    return this;
  }

  toString() {
    const x = {
      startingSide: this.startingSide,
      leftLeaf: this.leftLeaf
        ? Buffer.from(this.leftLeaf).toString("hex")
        : undefined,
      rightLeaf: this.rightLeaf
        ? Buffer.from(this.rightLeaf).toString("hex")
        : undefined,
      leftProofs: this.leftProofs.map((x) => [
        Buffer.from(x[0]).toString("hex"),
        x[1],
      ]),
      rightProofs: this.rightProofs.map((x) => [
        Buffer.from(x[0]).toString("hex"),
        x[1],
      ]),
      continuingSideProofs: this.continuingSideProofs.map((x) => [
        Buffer.from(x[0]).toString("hex"),
        x[1],
      ]),
      remainingProofs: this.remainingProofs.map((x) => [
        Buffer.from(x[0]).toString("hex"),
        x[1],
        x[2],
      ]),
      leftRightHeight: this.leftRightHeight,
      intersectingHeight: this.intersectingHeight,
    };
    return JSON.stringify(x);
  }

  toStringProof() {
    const x = {
      startingSide: this.startingSide,
      leftLeaf: this.leftLeaf
        ? Buffer.from(this.leftLeaf).toString("hex")
        : undefined,
      rightLeaf: this.rightLeaf
        ? Buffer.from(this.rightLeaf).toString("hex")
        : undefined,
      leftProofs: this.leftProofs
        .map((x) => {
          let l = new Uint8Array([x[1]]);

          return Buffer.concat([x[0], l]).toString("hex");
        })
        .join(""),

      rightProofs: this.rightProofs
        .map((x) => {
          let l = new Uint8Array([x[1]]);

          return Buffer.concat([l, x[0]]).toString("hex");
        })
        .join(""),
      continuingSideProofs: this.continuingSideProofs
        .map((x) => {
          let l = new Uint8Array([x[1]]);

          if (this.startingSide === "left") {
            return Buffer.concat([x[0], l]).toString("hex");
          } else {
            return Buffer.concat([l, x[0]]).toString("hex");
          }
        })
        .join(""),
      remainingProofs: this.remainingProofs
        .map((x) => {
          let l = new Uint8Array([x[1]]);
          if (x[2] === "left") {
            return Buffer.concat([new Uint8Array([0]), x[0], l]).toString(
              "hex"
            );
          } else {
            return Buffer.concat([new Uint8Array([1]), l, x[0]]).toString(
              "hex"
            );
          }
        })
        .join(""),
      leftRightHeight: this.leftRightHeight,
      intersectingHeight: this.intersectingHeight,
    };
    return JSON.stringify(x);
  }
}

export class Leaf {
  key: BitSet;
  value: Uint8Array;
  leafHash: Uint8Array;

  constructor(value: string | Buffer) {
    const bufferValue: Uint8Array =
      typeof value == "string"
        ? new TextEncoder().encode(value)
        : new Uint8Array(value);

    this.key = new BitSet(
      Buffer.from(blake2b(bufferValue, undefined, 32)).reverse()
    );

    this.value = bufferValue;

    this.leafHash = blake2b(
      Buffer.concat([leafBytes, blake2b(bufferValue, undefined, 32)]),
      undefined,
      32
    );
  }

  getHash() {
    return this.leafHash;
  }

  doInsert(key: BitSet, value: string | Buffer) {
    let other = new Leaf(value);

    let testBit = -1;

    while (!key.slice(testBit + 1).equals(this.key.slice(testBit + 1))) {
      testBit++;
    }

    if (testBit < 0) {
      const bufferValue: Uint8Array =
        typeof value == "string"
          ? new TextEncoder().encode(value)
          : new Uint8Array(value);
      console.log(blake2bHex(bufferValue, undefined, 32));
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

  doModificationProof(_key: BitSet, _mutProof: MerkleProof): MerkleProof {
    throw new Error("Not possible");
  }

  traverseLeft(mutProof: MerkleProof) {
    mutProof.rightLeaf = blake2b(this.value, undefined, 32);
  }

  traverseRight(mutProof: MerkleProof) {
    mutProof.leftLeaf = blake2b(this.value, undefined, 32);
  }

  doMemberProof(_key: BitSet): [Uint8Array, number, Side][] {
    throw new Error("Not possible");
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
      currentHeight = heightDiff - 1;
    } else if (childTwo instanceof Leaf) {
      const heightDiff = childOne instanceof Leaf ? 0 : childOne.height + 1;

      keyTwo = keyTwo.slice(heightDiff);
      currentHeight = heightDiff - 1;
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

  getHash() {
    return this.branchHash;
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

      if (leftHeight >= 0 && rightHeight < 0) {
        this.leftChild = this.leftChild.doInsert(key, value);
      } else if (leftHeight < 0 && rightHeight >= 0) {
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

  doModificationProof(key: BitSet, mutProof: MerkleProof) {
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

    if (key.equals(this.rightChild.key)) {
      mutProof.intersectingHeight = this.height;
      mutProof.startingSide = "left";
      this.leftChild.traverseRight(mutProof);
      return;
    } else if (key.equals(this.leftChild.key)) {
      mutProof.intersectingHeight = this.height;
      mutProof.startingSide = "right";
      this.rightChild.traverseLeft(mutProof);

      return;
    } else if (leftHeight >= 0 && rightHeight < 0) {
      this.leftChild.doModificationProof(key, mutProof);

      if (
        mutProof.startingSide === "left" &&
        typeof mutProof.rightLeaf === "undefined"
      ) {
        this.rightChild.traverseLeft(mutProof);
        mutProof.leftRightHeight = this.height;
      } else if (
        mutProof.startingSide === "right" &&
        typeof mutProof.leftLeaf === "undefined"
      ) {
        mutProof.insertContinuingSideProof(
          this.rightChild.getHash(),
          this.height
        );
      } else {
        mutProof.insertRemainingProof(
          this.rightChild.getHash(),
          this.height,
          "right"
        );
      }
      return;
    } else if (leftHeight < 0 && rightHeight >= 0) {
      this.rightChild.doModificationProof(key, mutProof);

      if (
        mutProof.startingSide === "right" &&
        typeof mutProof.leftLeaf === "undefined"
      ) {
        this.leftChild.traverseRight(mutProof);
        mutProof.leftRightHeight = this.height;
      } else if (
        mutProof.startingSide === "left" &&
        typeof mutProof.rightLeaf === "undefined"
      ) {
        mutProof.insertContinuingSideProof(
          this.leftChild.getHash(),
          this.height
        );
      } else {
        mutProof.insertRemainingProof(
          this.leftChild.getHash(),
          this.height,
          "left"
        );
      }

      return;
    } else {
      throw new Error("Impossible");
    }
  }

  traverseLeft(mutProof: MerkleProof) {
    this.leftChild.traverseLeft(mutProof);

    mutProof.insertRightProof(this.rightChild.getHash(), this.height);
  }

  traverseRight(mutProof: MerkleProof) {
    this.rightChild.traverseRight(mutProof);

    mutProof.insertLeftProof(this.leftChild.getHash(), this.height);
  }

  doMemberProof(key: BitSet): [Uint8Array, number, Side][] {
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

    if (key.equals(this.leftChild.key)) {
      return [[this.rightChild.getHash(), this.height, "right"]];
    } else if (key.equals(this.rightChild.key)) {
      return [[this.leftChild.getHash(), this.height, "left"]];
    } else if (leftHeight >= 0 && rightHeight < 0) {
      return [
        [this.rightChild.getHash(), this.height, "right"],
        ...this.leftChild.doMemberProof(key),
      ];
    } else if (leftHeight < 0 && rightHeight >= 0) {
      return [
        [this.leftChild.getHash(), this.height, "left"],
        ...this.rightChild.doMemberProof(key),
      ];
    } else {
      throw new Error("Impossible");
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

    const initialKey = new BitSet(
      Buffer.from(blake2b(bufferValue, undefined, 32)).reverse()
    );

    super.doInsert(initialKey, value);
  }

  modificationProof(value: string | Buffer) {
    const bufferValue: Uint8Array =
      typeof value == "string"
        ? new TextEncoder().encode(value)
        : new Uint8Array(value);

    const initialKey = new BitSet(
      Buffer.from(blake2b(bufferValue, undefined, 32)).reverse()
    );

    let merkleProof = new MerkleProof();

    super.doModificationProof(initialKey, merkleProof);

    return merkleProof;
  }

  memberProof(value: string | Buffer) {
    const bufferValue: Uint8Array =
      typeof value == "string"
        ? new TextEncoder().encode(value)
        : new Uint8Array(value);

    const initialKey = new BitSet(
      Buffer.from(blake2b(bufferValue, undefined, 32)).reverse()
    );

    return super.doMemberProof(initialKey).reverse();
  }
}
