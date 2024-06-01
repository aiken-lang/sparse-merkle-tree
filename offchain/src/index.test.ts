import { expect, test } from "vitest";
import { Buffer } from "buffer";
import * as fs from "fs";
import * as path from "path";

import { SparseMerkleTree } from "./index.js";
import { blake2bHex } from "blakejs";

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

  fruits.slice(0, 12).forEach((fruit) => {
    x.insert(fruit);
    rootList.push(x.branchHash);
  });

  const expected = {
    startingSide: "left",
    leftLeaf:
      "3378b5c960257ffe7c3e86d00563739bdf7db730e10732f6b943a4c1802fd05e",
    rightLeaf:
      "55d5551e8e1323d35afe53cf8698867c9de9a408e97ee968dc8414d527cc719c",
    leftProofs: [],
    rightProofs: [
      ["0bca11bb74090bc698bc7b811c23e87d97744b10c16f2c7d5e23d82bd5f41bea", 253],
    ],
    continuingSideProofs: [
      ["4ac5fceda4fe0ba6787bf5967fc6d24698d0e845ea69f7fec3e41f067928e9f1", 253],
    ],
    remainingProofs: [
      [
        "26363294ff627e13438ecc429926a7cb64686944ec0587128338e3b447dc30e5",
        255,
        "right",
      ],
    ],
    leftRightHeight: 254,
    intersectingHeight: 251,
  };

  const actual = x.modificationProof("grapefruit (0)");

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
});

test("Test Modification Proof2", () => {
  const x = new SparseMerkleTree();
  let rootList: Uint8Array[] = [];

  fruits.forEach((fruit) => {
    x.insert(fruit);

    rootList.push(x.branchHash);
  });

  const expected = {
    startingSide: "left",
    leftLeaf:
      "ba830de32503d8941eee8b8689332e8903841663d99c4442434858b1a147da75",
    rightLeaf:
      "c85531ce450e18f357f214ca0ef1f2bac4a010a1af5af81ddebf137608c5aad3",
    leftProofs: [],
    rightProofs: [
      ["0a45855e42b616c2ab268fb6419f821c68634637380683d0c894216f83ad6ef4", 253],
    ],
    continuingSideProofs: [
      ["bc0d60e5f1a745633d297f0275d0a6e51171a674b5246df446b6549207ec3bdd", 252],
      ["9763947dcfc708abcd0f5bfc8ccec310b91c1db4acd90582d7d2fd2aed3a3ee9", 253],
    ],
    remainingProofs: [
      [
        "4ade9ca0cbd69b8322a0744fa751b4d4a91a280e4945ba5874a0c3fbfe76524d",
        255,
        "left",
      ],
    ],
    leftRightHeight: 254,
    intersectingHeight: 250,
  };

  const actual = x.modificationProof("yuzu (0)");

  expect(actual.toString()).toStrictEqual(JSON.stringify(expected));
});

test("Test Modification Proof3", () => {
  const x = new SparseMerkleTree();
  let rootList: Uint8Array[] = [];

  const headerHashes = JSON.parse(fs.readFileSync("combined.json", "utf8"));

  headerHashes
    .slice(0, 12)
    .forEach((headerHash: { hash: string; merkleroot: string }) => {
      x.insert(Buffer.from(headerHash.hash, "hex"));
      console.log(headerHash.hash);
      console.log(
        blake2bHex(Buffer.from(headerHash.hash, "hex"), undefined, 32)
      );
      rootList.push(x.branchHash);
    });

  const expected = {
    startingSide: "right",
    leftLeaf:
      "d4021488c039595fcb330d4d4670fb038747e98e02f2eaed3a8ef1b21dc31620",
    rightLeaf:
      "ebb7a5b9485ebf3d53a9346b79ef0b2421871299f36d71e00c1dd19a02f70272",
    leftProofs: [
      ["d573180cc035518928c70571a35eb961685197fd1e4c0567dacfd4460615fa8b", 252],
    ],
    rightProofs: [
      ["b66272e4e204d0670fc0b75effbd3e2e3323da698ba22d80dbb082beacd0e5b0", 250],
    ],
    continuingSideProofs: [
      ["c66d906756f4d29c2f34819e5d6505b48e73524f5f259a03d1f27d4710c7cdbc", 252],
    ],
    remainingProofs: [
      [
        "c685d33527ad2dcf8b6450498ef57fddb840c787c50d234e349e7ca50d71b549",
        254,
        "left",
      ],
      [
        "e388b5fe613ee6ae037be1b0625fbf6f6624beb98e6b58bd3482c9c4294797b5",
        255,
        "left",
      ],
    ],
    leftRightHeight: 253,
    intersectingHeight: 251,
  };
  const actual = x.modificationProof(
    Buffer.from(
      "0000000097be56d606cdd9c54b04d4747e957d3608abe69198c661f2add73073",
      "hex"
    )
  );

  console.log(rootList.map((x) => Buffer.from(x).toString("hex")));

  expect(actual.toString()).toStrictEqual(JSON.stringify(expected));
});

test("Test Modification Proof4", () => {
  const x = new SparseMerkleTree();
  let rootList: Uint8Array[] = [];

  const headerHashes = JSON.parse(fs.readFileSync("combined.json", "utf8"));

  headerHashes
    .slice(0, 20000)
    .forEach((headerHash: { hash: string; merkleroot: string }) => {
      x.insert(Buffer.from(headerHash.hash, "hex"));
      rootList.push(x.branchHash);
    });

  headerHashes
    .slice(0, 20000)
    .slice(-2)
    .forEach((headerHash: { hash: string; merkleroot: string }) => {
      console.log(headerHash.hash);
      console.log(
        blake2bHex(Buffer.from(headerHash.hash, "hex"), undefined, 32)
      );
    });

  const expected = {
    startingSide: "left",
    leftLeaf:
      "bc1ca0cbcf9925bb28b1b5ae1f34db929c98ff7880e4c272c5aa27a9fee76fe1",
    rightLeaf:
      "bc22334d33a3839a9dac95bf25735406af5f02f95ae132360ab301891b1cfb6c",
    leftProofs: [],
    rightProofs: [
      ["da4ee37dfdf3c42bdfd0a6e9a82a9a5385a10ec3ea00144bc3c5ae60ec6a44ee", 243],
      ["aacffe9e203b017d02a84f0f85f7d08f09a58a30cac39852f8fa5fb43a408bea", 244],
    ],
    continuingSideProofs: [
      ["d9a1b49e8bfd5078a0650070e262285204982deb602b5ab539771b730b6d6ee1", 243],
      ["1eca8e2d3903bed86dc27e88456655020b15aab17b175e3ebaeda94d3c8b085f", 244],
    ],
    remainingProofs: [
      [
        "26bbffdd6cc91ab105c2a76b58b17697a51d938ea16b930e8c577a13aa467bb0",
        246,
        "right",
      ],
      [
        "d9dfca90ee9916311dc85cca454bcbbb28dec8de2e4d4fcdac5ec0159e9a9984",
        247,
        "right",
      ],
      [
        "f3904d9be863ff4fee423cb8e08f29111299c9a7717549e875e265a659cf5a2c",
        248,
        "right",
      ],
      [
        "ae59d09a8003fe3b62547c95454e9b268b15cedec3d4060d2e5eb3364e9c10e2",
        249,
        "right",
      ],
      [
        "62ab74209c26d3ee8add422ebb3e97d16b8f76a014c149482c6ceb2665c10b65",
        250,
        "left",
      ],
      [
        "37055c548a34c5480c73299f2f20af25a76f583e5b6b893e7955a8df22d58c3b",
        251,
        "left",
      ],
      [
        "42216e091635d737f234822cd386edc12a8243773716126f891fe0e4a60ca652",
        252,
        "left",
      ],
      [
        "62ffd39cbe7e6999bfd221067038f42456c3560c0db1d53c759372896cc54504",
        253,
        "left",
      ],
      [
        "766c637a5b6a2665d2f1af04ef1ea57e6039620604c2f42a6726085361a3c433",
        254,
        "right",
      ],
      [
        "b4442d490c6c35e3f98f5766bb9b56f69cca2c9f459333551f60cfd898aace0a",
        255,
        "left",
      ],
    ],
    leftRightHeight: 245,
    intersectingHeight: 240,
  };

  const actual = x.modificationProof(
    Buffer.from(
      "00000000ba36eb929dc90170a96ee3efb76cbebee0e0e5c4da9eb0b6e74d9124",
      "hex"
    )
  );

  const aaaa = {
    startingSide: "left",
    leftLeaf:
      "bc1ca0cbcf9925bb28b1b5ae1f34db929c98ff7880e4c272c5aa27a9fee76fe1",
    rightLeaf:
      "bc22334d33a3839a9dac95bf25735406af5f02f95ae132360ab301891b1cfb6c",
    leftProofs: [],
    rightProofs: [
      "f3da4ee37dfdf3c42bdfd0a6e9a82a9a5385a10ec3ea00144bc3c5ae60ec6a44ee",
      "f4aacffe9e203b017d02a84f0f85f7d08f09a58a30cac39852f8fa5fb43a408bea",
    ],
    continuingSideProofs: [
      "d9a1b49e8bfd5078a0650070e262285204982deb602b5ab539771b730b6d6ee1f3",
      "1eca8e2d3903bed86dc27e88456655020b15aab17b175e3ebaeda94d3c8b085ff4",
    ],
    remainingProofs: [
      "01f626bbffdd6cc91ab105c2a76b58b17697a51d938ea16b930e8c577a13aa467bb0",
      "01f7d9dfca90ee9916311dc85cca454bcbbb28dec8de2e4d4fcdac5ec0159e9a9984",
      "01f8f3904d9be863ff4fee423cb8e08f29111299c9a7717549e875e265a659cf5a2c",
      "01f9ae59d09a8003fe3b62547c95454e9b268b15cedec3d4060d2e5eb3364e9c10e2",
      "0062ab74209c26d3ee8add422ebb3e97d16b8f76a014c149482c6ceb2665c10b65fa",
      "0037055c548a34c5480c73299f2f20af25a76f583e5b6b893e7955a8df22d58c3bfb",
      "0042216e091635d737f234822cd386edc12a8243773716126f891fe0e4a60ca652fc",
      "0062ffd39cbe7e6999bfd221067038f42456c3560c0db1d53c759372896cc54504fd",
      "01fe766c637a5b6a2665d2f1af04ef1ea57e6039620604c2f42a6726085361a3c433",
      "00b4442d490c6c35e3f98f5766bb9b56f69cca2c9f459333551f60cfd898aace0aff",
    ],
    leftRightHeight: 245,
    intersectingHeight: 240,
  };

  console.log(actual.toStringProof());

  console.log(rootList.slice(-2).map((x) => Buffer.from(x).toString("hex")));

  expect(actual.toString()).toStrictEqual(JSON.stringify(expected));
});
