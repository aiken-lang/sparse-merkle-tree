import { expect, test } from "vitest";
import { Buffer } from "buffer";

import { SparseMerkleTree } from "./index.js";

test("Test Insert", () => {
  const x = new SparseMerkleTree();
  let rootList = [x.branchHash];
  const expectedList = [
    "ae671c31cece3444d2dd9240939e5c63c9b6ec79e6710b7a777f09d539a29d42",
    "18c8dbcc059576ec251c90862baee3387c4ea916ef72e6f7dbf15502521ebed2",
    "49148fa603b03d70fff1733cb9a70a35b9057637e11cde68e30f6f624b001504",
    "9ea42e89c070ee103f27ae748c0aa9ce268d2f44e66568423409fa4f659cdb7a",
    "8333b7d8020aa5101ae770c2b8ea84ad84834ea106413d309fbbf226816b6a17",
    "e53502fcf8e19ddd4130fb7430c89f7092e96493d7081486c8b9f452217096df",
    "d3161d3695bfb1ddedb5217a712350661bb8042ee7a73deec3686730ac872600",
    "913b8548e5bd6531610e5eacce933ffec3a29575f5e384fb795320d15ea28c9b",
    "5a812ad3240bc532aea6f0b8427ccf929a20bdd0a08bcad062207b14a65e9be8",
    "5cd33d77b3e53cd5433d5c56fb0cc3190a97a09e8e43382dac90883154f75885",
    "ce21ae7b870c1012db2b9d469e95a05540ad74640c236776139e52118d39f2fc",
    "0170b41f8f90f96eb95a0dfc66b959fb4e7060ed738ee162076d03597a0f468f",
    "92cc9d3ed08668c5d71243ccac72b76b46c924e5cee13583665a13920b244e23",
  ];

  x.insert("apple (0)");

  rootList.push(x.branchHash);

  x.insert("apricot (0)");

  rootList.push(x.branchHash);

  x.insert("banana (328)");

  rootList.push(x.branchHash);

  x.insert("blackberry (0)");

  rootList.push(x.branchHash);

  x.insert("blueberry (92383)");

  rootList.push(x.branchHash);

  x.insert("cherry (0)");

  rootList.push(x.branchHash);

  x.insert("coconut (0)");

  rootList.push(x.branchHash);

  x.insert("cranberry (0)");

  rootList.push(x.branchHash);

  x.insert("durian (0)");

  rootList.push(x.branchHash);

  x.insert("fig (0)");

  rootList.push(x.branchHash);

  x.insert("grape (110606)");

  rootList.push(x.branchHash);

  x.insert("grapefruit (0)");

  rootList.push(x.branchHash);

  expect(rootList.map((x) => Buffer.from(x).toString("hex"))).toStrictEqual(
    expectedList
  );
});

test("Test Modification Proof", () => {
  const x = new SparseMerkleTree();
  let rootList: Uint8Array[] = [];
  const expectedList: string[] = [];

  x.insert("apple (0)");
  x.insert("apricot (0)");
  x.insert("banana (328)");
  x.insert("blackberry (0)");
  x.insert("blueberry (92383)");
  x.insert("cherry (0)");
  x.insert("coconut (0)");
  x.insert("cranberry (0)");
  x.insert("durian (0)");
  x.insert("fig (0)");
  x.insert("grape (110606)");

  const other = x.modificationProof("grape (110606)");

  console.log(other.toString(), "\n\n");

  x.insert("grapefruit (0)");

  const expected = {
    startingSide: "left",
    remainingProofs: [
      [
        "26363294ff627e13438ecc429926a7cb64686944ec0587128338e3b447dc30e5",
        255,
        "right",
      ],
    ],
    leftLeaf:
      "3378b5c960257ffe7c3e86d00563739bdf7db730e10732f6b943a4c1802fd05e",
    rightLeaf:
      "55d5551e8e1323d35afe53cf8698867c9de9a408e97ee968dc8414d527cc719c",
    leftProofs: [],
    rightProofs: [
      ["0bca11bb74090bc698bc7b811c23e87d97744b10c16f2c7d5e23d82bd5f41bea", 253],
    ],
    continuingSideProofs: [
      ["3d7b9d20ff5e977c69307d9d264fe6b36cd0fc08b390578b09d33a9f044d77dd", 253],
    ],
    intersectingHeight: 251,
    leftRightHeight: 254,
  };

  const actual = x.modificationProof("grapefruit (0)");

  console.log(actual.toString());

  expect(actual.toString()).toStrictEqual(JSON.stringify(expected));
});

test("Test Member Proof", () => {
  const x = new SparseMerkleTree();
  let rootList: Uint8Array[] = [];
  const expectedList: string[] = [];

  x.insert("apple (0)");
  x.insert("apricot (0)");
  x.insert("banana (328)");
  x.insert("blackberry (0)");
  x.insert("blueberry (92383)");
  x.insert("cherry (0)");
  x.insert("coconut (0)");
  x.insert("cranberry (0)");
  x.insert("durian (0)");
  x.insert("fig (0)");
  x.insert("grape (110606)");
  x.insert("grapefruit (0)");

  const thing = x.memberProof("grapefruit (0)");

  console.log(thing);
});
