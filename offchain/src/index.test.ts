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

  expect(actual.toString()).toStrictEqual(JSON.stringify(expected));
});

test("Test Modification Proof5", () => {
  const x = new SparseMerkleTree();
  let rootList: Uint8Array[] = [];

  const headerHashes = JSON.parse(fs.readFileSync("combined.json", "utf8"));

  headerHashes
    .slice(0, 50000)
    .forEach((headerHash: { hash: string; merkleroot: string }) => {
      x.insert(Buffer.from(headerHash.hash, "hex"));
      rootList.push(x.branchHash);
    });

  headerHashes
    .slice(0, 50000)
    .slice(-2)
    .forEach((headerHash: { hash: string; merkleroot: string }) => {
      console.log(headerHash.hash);
      console.log(
        blake2bHex(Buffer.from(headerHash.hash, "hex"), undefined, 32)
      );
    });

  const expected = {
    startingSide: "right",
    leftLeaf:
      "57db583bfd56b6ed83cbb2aad4b70d2ecc6ce691d16ce745fe1d0f99d1ab5fbf",
    rightLeaf:
      "57df21077ec27c7bf58f1632cdc838e984ca3f793d15751a778e4edd4db92707",
    leftProofs: [
      ["a1a0dbb452b960f2a92c2356254e79900ea66eba6841d22f784cda43bb42edd8", 238],
      ["5da061a1d57213c16d1c02908af56680d0818c55994ca6ef412c410d6aa23f14", 240],
      ["486b9c7906b1f040e7debd938da602e7721cc23a1da7f787dd09ba5bb2f944d2", 241],
    ],
    rightProofs: [
      ["8d09abdb04c35ac5ca961bcf0dee1bd63208de8741786dff63d3529f0be05edf", 239],
    ],
    continuingSideProofs: [],
    remainingProofs: [
      [
        "5acfd366a9fe5d2197aaef88b329de066ab7b18955290b8892342e35772bb6ed",
        243,
        "left",
      ],
      [
        "4ec73e5e55bf895ae674cd1212c5c1f88e77381c3197900563226af85751739b",
        244,
        "left",
      ],
      [
        "570d47de125137281e38951d8f17fd52a2c727dd9a6f68a5ef0ab05815e0a91b",
        245,
        "right",
      ],
      [
        "df274cc145f0700ec9959aa2d566d2d7fb80efa1bb945e9efe553e1abf4c90f7",
        246,
        "left",
      ],
      [
        "9d52f54dd3cf7409112539e6ad264a51b9e14fdd63310debf18fa7277250ece0",
        247,
        "left",
      ],
      [
        "eab3d7c485dd7c698ce6d7190723e3885087002547d287acbe9187b1770a3140",
        248,
        "left",
      ],
      [
        "15a78db8eb8f3879a28f61d40f043cd6c7f77afc279070fac74189f6f4992afb",
        249,
        "left",
      ],
      [
        "67672a386b3b20f9ee156a43a368f1a5cbdf88644c0770db02d67478303c4f41",
        250,
        "left",
      ],
      [
        "b4e93db8bfb415c33ffafb6a243546d3df6530d82ac637658cb5acbbc24997e8",
        251,
        "right",
      ],
      [
        "05266e1e4b78e077cacea88d4ead56d879eee0557bde1212c8486ccb173b13d2",
        252,
        "left",
      ],
      [
        "409d13ae10079e23050258d62bc6be752ae4a68c1cf50e84f5807c8b7acca563",
        253,
        "right",
      ],
      [
        "c691e6ce4be8bd9d5e777c582a7fd51b31c41896bab603481ef66856f4128636",
        254,
        "left",
      ],
      [
        "af14d25ad97e48d5cb2559b4bf4b1eab08b55b2bc9e674211b88618672882970",
        255,
        "right",
      ],
    ],
    leftRightHeight: 242,
    intersectingHeight: 241,
  };

  const actual = x.modificationProof(
    Buffer.from(
      "0000000007db79e3b3c9575767f2e142565d5b120580d0c80844af75d38e6c6f",
      "hex"
    )
  );

  console.log(actual.toStringProof());

  console.log(rootList.slice(-2).map((x) => Buffer.from(x).toString("hex")));

  expect(actual.toString()).toStrictEqual(JSON.stringify(expected));
});

test("Test Modification Proof6", () => {
  const x = new SparseMerkleTree();
  let rootList: Uint8Array[] = [];

  const headerHashes = JSON.parse(fs.readFileSync("combined.json", "utf8"));

  headerHashes
    .slice(0, 200000)
    .forEach((headerHash: { hash: string; merkleroot: string }) => {
      x.insert(Buffer.from(headerHash.hash, "hex"));
      rootList.push(x.branchHash);
    });

  headerHashes
    .slice(0, 200000)
    .slice(-2)
    .forEach((headerHash: { hash: string; merkleroot: string }) => {
      console.log(headerHash.hash);
      console.log(
        blake2bHex(Buffer.from(headerHash.hash, "hex"), undefined, 32)
      );
    });

  const expected = {
    startingSide: "right",
    leftLeaf:
      "59aa493eeff81348598647d1355dd4b40d841801b191b06b0a8c8b0e2532d095",
    rightLeaf:
      "59ab5a76d8b506cc0c1e0b72051b1ac87651db0ec083dbd66852c985ba91505e",
    leftProofs: [],
    rightProofs: [],
    continuingSideProofs: [
      ["937186e1bde24cb3bb599a21037ea19746f1f79f444aa1eaf66479f0237418e9", 239],
    ],
    remainingProofs: [
      [
        "18d9198dea65915c093c607a6478f38b0dcf74b16d849293cece08dd0a3830a6",
        241,
        "left",
      ],
      [
        "d32ebc686999824ddd4ad92433d36b86bbf75b44846a76667454c87f2a102432",
        242,
        "right",
      ],
      [
        "1f673a231083de873c715efd84bc7b5ecbac390a7341949fde5072817e8176d3",
        243,
        "left",
      ],
      [
        "26124666b1fa08638c52557d5af63408676b14910135d498f906fa5b1dd95cfe",
        244,
        "right",
      ],
      [
        "a29774309b6c842bc22355ad3834fcff9e5e59467a89db008965504a7c9b09d0",
        245,
        "left",
      ],
      [
        "ea1f315673ff81ec6ab824e1b14ebe4714d0a041525aa35ed9e96f5fcde34d39",
        246,
        "right",
      ],
      [
        "2b9c25c23127a4c6a390b244dd97cb668ae72288bbfed45274d9bcb982431ae5",
        247,
        "left",
      ],
      [
        "d7303ea6f00c4c962a9dfab3990c96418357801cdeb8e6f5c9a7866261a8c076",
        248,
        "left",
      ],
      [
        "92b9a733701dd1649421ba99c117990f1a826f9d667cb122fc59b9c75c1d5e0a",
        249,
        "right",
      ],
      [
        "a911b5813c4401c95e2e557def47ac0708a318ef3d7becb2e0f5e16a0ff63a05",
        250,
        "right",
      ],
      [
        "7e9e7322b24c5f0359e22b4e4bcf2d99c286340dce488665a620f7897f5ee7e6",
        251,
        "left",
      ],
      [
        "2e86e68c0a5de6c9ff799a2427c78e41632afc7f79a199256aaf2c00eb3e0063",
        252,
        "left",
      ],
      [
        "a3e1be0e3fb3d814f0a150f3877fbcb990cf27c3c5cc6037ac5887d1144de4d3",
        253,
        "right",
      ],
      [
        "26b3e9f20d98eadc1687d5e2b054e7447ba7f24193a68d1d7950ae0e2ea443f7",
        254,
        "left",
      ],
      [
        "92580d8a2f251909e1cc70bc54da0fcb37962b04d7e7c101a0e4f365b1921a26",
        255,
        "right",
      ],
    ],
    leftRightHeight: 240,
    intersectingHeight: 238,
  };

  const actual = x.modificationProof(
    Buffer.from(
      "0000000000000553828611e5ead40e4d153f09557573bf89dc637b9880859789",
      "hex"
    )
  );

  console.log(actual.toStringProof());

  console.log(rootList.slice(-2).map((x) => Buffer.from(x).toString("hex")));

  const aas = {
    startingSide: "right",
    leftLeaf:
      "59aa493eeff81348598647d1355dd4b40d841801b191b06b0a8c8b0e2532d095",
    rightLeaf:
      "59ab5a76d8b506cc0c1e0b72051b1ac87651db0ec083dbd66852c985ba91505e",
    leftProofs: "",
    rightProofs: "",
    continuingSideProofs:
      "ef937186e1bde24cb3bb599a21037ea19746f1f79f444aa1eaf66479f0237418e9",
    remainingProofs:
      "0018d9198dea65915c093c607a6478f38b0dcf74b16d849293cece08dd0a3830a6f101f2d32ebc686999824ddd4ad92433d36b86bbf75b44846a76667454c87f2a102432001f673a231083de873c715efd84bc7b5ecbac390a7341949fde5072817e8176d3f301f426124666b1fa08638c52557d5af63408676b14910135d498f906fa5b1dd95cfe00a29774309b6c842bc22355ad3834fcff9e5e59467a89db008965504a7c9b09d0f501f6ea1f315673ff81ec6ab824e1b14ebe4714d0a041525aa35ed9e96f5fcde34d39002b9c25c23127a4c6a390b244dd97cb668ae72288bbfed45274d9bcb982431ae5f700d7303ea6f00c4c962a9dfab3990c96418357801cdeb8e6f5c9a7866261a8c076f801f992b9a733701dd1649421ba99c117990f1a826f9d667cb122fc59b9c75c1d5e0a01faa911b5813c4401c95e2e557def47ac0708a318ef3d7becb2e0f5e16a0ff63a05007e9e7322b24c5f0359e22b4e4bcf2d99c286340dce488665a620f7897f5ee7e6fb002e86e68c0a5de6c9ff799a2427c78e41632afc7f79a199256aaf2c00eb3e0063fc01fda3e1be0e3fb3d814f0a150f3877fbcb990cf27c3c5cc6037ac5887d1144de4d30026b3e9f20d98eadc1687d5e2b054e7447ba7f24193a68d1d7950ae0e2ea443f7fe01ff92580d8a2f251909e1cc70bc54da0fcb37962b04d7e7c101a0e4f365b1921a26",
    leftRightHeight: 240,
    intersectingHeight: 238,
  };

  expect(actual.toString()).toStrictEqual(JSON.stringify(expected));
});

test("Test Modification Proof7", () => {
  const x = new SparseMerkleTree();
  let rootList: Uint8Array[] = [];

  const headerHashes = JSON.parse(fs.readFileSync("combined.json", "utf8"));

  headerHashes
    .slice(0, 800000)
    .forEach((headerHash: { hash: string; merkleroot: string }) => {
      x.insert(Buffer.from(headerHash.hash, "hex"));
      rootList.push(x.branchHash);
    });

  headerHashes
    .slice(0, 800000)
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
      "4d944b2d33ac3242a864bbfc70eab8a8c1531cb0cff26d02398f26ca95132b6a",
    rightLeaf:
      "4d9453605d145d468b35527442eaca3407702da892361cc383fdc65807b3c921",
    leftProofs: [
      ["be6958d13960863e9d34f789453f13e8f999aae3077f8bd221eb443900f50656", 232],
    ],
    rightProofs: [
      ["6f09f86ac9464567a82521a4d117d78f2f30f1f13d213039b3c34ad1063a3c33", 234],
    ],
    continuingSideProofs: [
      ["4b795c9b28cdc81d3d80e2c998628b0d2ebb7ca90bac8858e953540b1dbe418a", 235],
    ],
    remainingProofs: [
      [
        "29af690b2be479e6885fcce649a53f4d7248080efdce0d9b25f39f82fb2d48b3",
        237,
        "right",
      ],
      [
        "f8cee02011790b5e460ec687ded4a9157b924cb06b42bc32a092bac87a9fc557",
        238,
        "left",
      ],
      [
        "8c5ff1208dcc7a67cc3aa50fd00338596651be92c53cb737c3674bd485547bdf",
        239,
        "right",
      ],
      [
        "e91367c327c548a186d3d94b932c23dd0a0c0ac27e427f9c1b8c9a3150ca2858",
        240,
        "right",
      ],
      [
        "fff7ee68e975d077eae8d2afde82bafad93d635fd3ea51cc2489a13b711d42ab",
        241,
        "right",
      ],
      [
        "ed2390a084352758723d15a4a2d17fea55ea6de611211c806f94d334397769fb",
        242,
        "left",
      ],
      [
        "7daa5b1a475e4778a6ffef1b400c452e6bc39cf8b5b8564149180d752f744314",
        243,
        "right",
      ],
      [
        "66ac374ccc44a6eaf5e96be71133fece7ef6285ca2c028fb2569d3d8852a720e",
        244,
        "left",
      ],
      [
        "fc6e932402c18ea51231de55ebf8310e0604be8f7944499a1d9890bf1e40cc70",
        245,
        "right",
      ],
      [
        "9d0a161e22c7de97f93ed5e95c876ddeba207ea726a3e3f80fd2cc3ffc1ad8a4",
        246,
        "right",
      ],
      [
        "637083cbcdd017838c67e51095e0e57eb10d56b180c21eb6c18bbb9bc6e7420f",
        247,
        "left",
      ],
      [
        "86237bc0917775530d179e2cfca093159e48bf9ab055d19f7f4e837d9ed8dfd3",
        248,
        "left",
      ],
      [
        "7e2d5ae9f52508c861a45394dd4c9e7e6cc3819d1e1d112405f5f52dbc4c00fc",
        249,
        "right",
      ],
      [
        "a72dfe78d77d05310f6650aa3c0a8da9ff1051af33e4a01c0f6b9e27f1cc954e",
        250,
        "left",
      ],
      [
        "8216de938a3846be972a9637bc437f4277d7300d2479d5702f1dd2e3ae464c3f",
        251,
        "left",
      ],
      [
        "abf3db6deb2a007ad43ed7f58507fec40480928b5e305182660946d008ada242",
        252,
        "right",
      ],
      [
        "1bc9696bee26ea5054fd7549203d77cd2a96768f1c22e8c3b5a555cd4f2aef60",
        253,
        "right",
      ],
      [
        "f793c95b8a059e5c8b4e076601d4a61583fbc1a1b6944e86e13f524addad02e7",
        254,
        "left",
      ],
      [
        "d45f5018aa3c6c2f5277146d87ce8827e44a4cfdaf888e79e1353c411adb00c0",
        255,
        "right",
      ],
    ],
    leftRightHeight: 236,
    intersectingHeight: 234,
  };

  const actual = x.modificationProof(
    Buffer.from(
      "00000000000000000004a8437dbe7995eacf42daa014088d04e5010a44e64f42",
      "hex"
    )
  );

  console.log(actual.toStringProof());

  console.log(rootList.slice(-2).map((x) => Buffer.from(x).toString("hex")));

  const aadfa = {
    startingSide: "left",
    leftLeaf:
      "4d944b2d33ac3242a864bbfc70eab8a8c1531cb0cff26d02398f26ca95132b6a",
    rightLeaf:
      "4d9453605d145d468b35527442eaca3407702da892361cc383fdc65807b3c921",
    leftProofs:
      "be6958d13960863e9d34f789453f13e8f999aae3077f8bd221eb443900f50656e8",
    rightProofs:
      "ea6f09f86ac9464567a82521a4d117d78f2f30f1f13d213039b3c34ad1063a3c33",
    continuingSideProofs:
      "4b795c9b28cdc81d3d80e2c998628b0d2ebb7ca90bac8858e953540b1dbe418aeb",
    remainingProofs:
      "01ed29af690b2be479e6885fcce649a53f4d7248080efdce0d9b25f39f82fb2d48b300f8cee02011790b5e460ec687ded4a9157b924cb06b42bc32a092bac87a9fc557ee01ef8c5ff1208dcc7a67cc3aa50fd00338596651be92c53cb737c3674bd485547bdf01f0e91367c327c548a186d3d94b932c23dd0a0c0ac27e427f9c1b8c9a3150ca285801f1fff7ee68e975d077eae8d2afde82bafad93d635fd3ea51cc2489a13b711d42ab00ed2390a084352758723d15a4a2d17fea55ea6de611211c806f94d334397769fbf201f37daa5b1a475e4778a6ffef1b400c452e6bc39cf8b5b8564149180d752f7443140066ac374ccc44a6eaf5e96be71133fece7ef6285ca2c028fb2569d3d8852a720ef401f5fc6e932402c18ea51231de55ebf8310e0604be8f7944499a1d9890bf1e40cc7001f69d0a161e22c7de97f93ed5e95c876ddeba207ea726a3e3f80fd2cc3ffc1ad8a400637083cbcdd017838c67e51095e0e57eb10d56b180c21eb6c18bbb9bc6e7420ff70086237bc0917775530d179e2cfca093159e48bf9ab055d19f7f4e837d9ed8dfd3f801f97e2d5ae9f52508c861a45394dd4c9e7e6cc3819d1e1d112405f5f52dbc4c00fc00a72dfe78d77d05310f6650aa3c0a8da9ff1051af33e4a01c0f6b9e27f1cc954efa008216de938a3846be972a9637bc437f4277d7300d2479d5702f1dd2e3ae464c3ffb01fcabf3db6deb2a007ad43ed7f58507fec40480928b5e305182660946d008ada24201fd1bc9696bee26ea5054fd7549203d77cd2a96768f1c22e8c3b5a555cd4f2aef6000f793c95b8a059e5c8b4e076601d4a61583fbc1a1b6944e86e13f524addad02e7fe01ffd45f5018aa3c6c2f5277146d87ce8827e44a4cfdaf888e79e1353c411adb00c0",
    leftRightHeight: 236,
    intersectingHeight: 234,
  };

  expect(actual.toString()).toStrictEqual(JSON.stringify(expected));
});
