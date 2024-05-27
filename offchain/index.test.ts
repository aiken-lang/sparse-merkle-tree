import { Leaf, SparseMerkleTree } from ".";
import { Buffer } from "buffer";

test("Test 1", () => {
  const x = new SparseMerkleTree();

  console.log(x.leftChild.key.toString(), x.rightChild.key.toString());

  console.log(
    x.leftChild instanceof Leaf
      ? Buffer.from(x.leftChild.leafHash).toString("hex")
      : "Branch"
  );
  console.log(
    x.rightChild instanceof Leaf
      ? Buffer.from(x.rightChild.leafHash).toString("hex")
      : "Branch"
  );

  console.log(x);
  console.log("Root Hash", Buffer.from(x.branchHash).toString("hex"));
});
