import { expect, test } from "vitest";
import { Buffer } from "buffer";

import { SparseMerkleTree } from "./index.js";

const fruits = [
  "apple (0)",
  "apricot (0)",
  "banana (328)",
  "blackberry (0)",
  "blueberry (92383)",
  "cherry (0)",
  "coconut (0)",
  "cranberry (0)",
  "durian (0)",
  "fig (0)",
  "grape (110606)",
  "grapefruit (0)",
  "guava (0)",
  "kiwi (0)",
  "kumquat (0)",
  "lemon (37694)",
  "lime (0)",
  "mango (0)",
  "orange (36703)",
  "papaya (0)",
  "passionfruit (0)",
  "peach (0)",
  "pear (0)",
  "pineapple (0)",
  "plum (0)",
  "pomegranate (113)",
  "raspberry (0)",
  "strawberry (0)",
  "watermelon (20)",
  "yuzu (0)",
];

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

  fruits.slice(0, 12).forEach((fruit) => {
    x.insert(fruit);
    rootList.push(x.branchHash);
  });

  expect(rootList.map((x) => Buffer.from(x).toString("hex"))).toStrictEqual(
    expectedList
  );
});

test("Test Modification Proof", () => {
  const x = new SparseMerkleTree();
  let rootList: Uint8Array[] = [];
  const expectedList: string[] = [];

  fruits.slice(0, 12).forEach((fruit) => {
    x.insert(fruit);
    rootList.push(x.branchHash);
  });

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

test("Test Modification Proof2", () => {
  const x = new SparseMerkleTree();
  let rootList: Uint8Array[] = [];

  fruits.slice(0, 15).forEach((fruit) => {
    x.insert(fruit);
    console.log(fruit);
    rootList.push(x.branchHash);
  });

  console.log(rootList.map((x) => Buffer.from(x).toString("hex")));

  const a = {
    startingSide: "left",
    remainingProofs: [
      [
        "dbb028d68f52c20d4055736b69101407d2aefa8d09e9bb7e3ea49f649a6155d3",
        251,
        "left",
      ],
      [
        "ad29ecde0090b8b3098d28675be169f0feda70139ea1dd2c3470620036e01ed7",
        254,
        "right",
      ],
      [
        "ef4267ae7f358032de7a4b03a94e0053c8b2053f7f3192b2d4d3b3de58311177",
        255,
        "left",
      ],
    ],
    leftLeaf:
      "a909ba8699e34f8a78bacd04266b57f36ff3a758b93c0c31b0aaa18ba0be1e87",
    rightLeaf:
      "af7cd63fd75f935961ba7048b7f81244366198bd43fa60dfc43195a61507b859",
    leftProofs: [],
    rightProofs: [],
    continuingSideProofs: [],
    intersectingHeight: 249,
    leftRightHeight: 250,
  };

  const expected = {
    startingSide: "left",
    remainingProofs: [
      [
        "4ade9ca0cbd69b8322a0744fa751b4d4a91a280e4945ba5874a0c3fbfe76524d",
        255,
        "left",
      ],
    ],
    leftLeaf:
      "ba830de32503d8941eee8b8689332e8903841663d99c4442434858b1a147da75",
    rightLeaf:
      "c85531ce450e18f357f214ca0ef1f2bac4a010a1af5af81ddebf137608c5aad3",
    leftProofs: [],
    rightProofs: [
      ["0a45855e42b616c2ab268fb6419f821c68634637380683d0c894216f83ad6ef4", 253],
    ],
    continuingSideProofs: [
      ["7bd9009653a1b6d1751b961be9204676d501614fe438f61e3ccf689ece1b5b65", 252],
      ["61a457f71e181ddf47baddd3abdcca35e2b25472c17b11871d41966e69bb4bfb", 253],
    ],
    leftRightHeight: 254,
    intersectingHeight: 250,
  };

  const actual = x.modificationProof("kumquat (0)");

  console.log(actual.toString());

  expect(actual.toString()).toStrictEqual(JSON.stringify(expected));
});
