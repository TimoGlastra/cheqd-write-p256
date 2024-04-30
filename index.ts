import {
  AbstractCheqdSDKModule,
  CheqdSigningStargateClient,
  createCheqdSDK,
  DIDDocument,
  DIDModule,
} from "@cheqd/sdk";
import { createMsgCreateDidDocPayloadToSign } from "@cheqd/sdk/utils";
import { DirectSecp256k1HdWallet } from "@cosmjs/proto-signing";
import { randomUUID } from "node:crypto";
import type { SignInfo } from "@cheqd/ts-proto/cheqd/did/v2";
import { Jwk, Key } from "@hyperledger/aries-askar-nodejs";

const publicKeyHex =
  "04b71388fced2daee34793f74a7dfa982e37ce539a728233bcadaec298fc4ee422165b8db13e657f9c7b27b35364f523ad11fab29d717606140cc6312ec2c685cc";
const privateKeyHex =
  "4bd22700ec3450b5f27e47ba70c233a680c981ab02c1432a859ae23111bef377";

const hexToUintArray = (hex) => {
  const a = [];
  for (let i = 0, len = hex.length; i < len; i += 2) {
    a.push(parseInt(hex.substr(i, 2), 16));
  }
  return new Uint8Array(a);
};

const hexToArrayBuf = (hex) => {
  return hexToUintArray(hex).buffer;
};

const arrayBufToBase64UrlEncode = (buf) => {
  let binary = "";
  const bytes = new Uint8Array(buf);
  for (var i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\//g, "_").replace(/=/g, "").replace(/\+/g, "-");
};

const mnemonic =
  "sketch mountain erode window enact net enrich smoke claim kangaroo another visual write meat latin bacon pulp similar forum guilt father state erase bright";

async function run() {
  const sdk = await createCheqdSDK({
    modules: [DIDModule as unknown as AbstractCheqdSDKModule],
    rpcUrl: "https://rpc.cheqd.network",
    wallet: await DirectSecp256k1HdWallet.fromMnemonic(mnemonic, {
      prefix: "cheqd",
    }),
  });

  const did = `did:cheqd:testnet:${randomUUID()}`;

  const p256Key = Key.fromJwk({
    jwk: Jwk.fromJson({
      kty: "EC",
      crv: "P-256",
      d: arrayBufToBase64UrlEncode(hexToArrayBuf(privateKeyHex)),
      x: arrayBufToBase64UrlEncode(hexToArrayBuf(publicKeyHex).slice(1, 33)),
      y: arrayBufToBase64UrlEncode(hexToArrayBuf(publicKeyHex).slice(33, 66)),
    }),
  });
  const versionId = randomUUID();

  const didDocumentJson = {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
    ],
    id: did,
    verificationMethod: [
      {
        id: `${did}#key-1`,
        controller: did,
        type: "JsonWebKey2020",
        publicKeyJwk: p256Key.jwkPublic,
      },
    ],
  };

  const payloadToSign = await createMsgCreateDidDocPayloadToSign(
    didDocumentJson as DIDDocument,
    versionId
  );
  const cheqdSdkSignInfo = await CheqdSigningStargateClient.signIdentityTx(
    payloadToSign,
    [
      {
        privateKeyHex,
        verificationMethodId: `${did}#key-1`,
        keyType: "P256",
      },
    ]
  );

  const customSignInfo = [
    {
      signature: p256Key.signMessage({
        message: payloadToSign,
      }),
      verificationMethodId: `${did}#key-1`,
    },
  ] satisfies SignInfo[];

  console.log({
    cheqdSignatures: cheqdSdkSignInfo.map((s) =>
      Buffer.from(s.signature).toString("hex")
    ),
    customSignatures: customSignInfo.map((s) =>
      Buffer.from(s.signature).toString("hex")
    ),
  });

  const result = await sdk.createDidDocTx(
    cheqdSdkSignInfo,
    didDocumentJson as DIDDocument,
    "",
    undefined,
    undefined,
    versionId
  );

  console.log(result);
}

run();
