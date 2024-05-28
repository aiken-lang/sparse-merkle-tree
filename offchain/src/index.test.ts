import { expect, test } from "vitest";
import { Buffer } from "buffer";

import { Leaf, SparseMerkleTree } from "./index.js";

test("Test 1", () => {
  const x = new SparseMerkleTree();

  console.log("Root Hash", Buffer.from(x.branchHash).toString("hex"));

  x.insert("apple (0)");

  console.log("Root Hash", Buffer.from(x.branchHash).toString("hex"));
});
