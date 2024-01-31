// routes.js
import express from "express";
import { v4 as uuidv4 } from "uuid";
import jwt from "jsonwebtoken";
import fs from "fs";
import jwkToPem from "jwk-to-pem";
import { Resolver } from "did-resolver";
import { getResolver } from "@cef-ebsi/key-did-resolver";
import crypto from "crypto";
import { util } from "@cef-ebsi/key-did-resolver";
import base58 from "bs58";
import * as jose from "jose";

const dvvRouter = express.Router();

const ngrok = process.env.NGROK;

const privateKey = fs.readFileSync("./private_key_384.pem", "utf-8");
const publicKey = fs.readFileSync("./public_key_384.pem", "utf-8");

// Generate X25519 key pair
const privateKeyEncrypt = fs.readFileSync("privateEnc.pem");
// Read public key from file
const publicKeyEncrypt = fs.readFileSync("publicEnc.pem");

// console.log(privateKeyEncrypt)
// console.log(publicKeyEncrypt)

// Encode the public key in Base58 format
const publicKeyEncBase58 = base58.encode(publicKeyEncrypt);

// Create the JWK object
const jwkEncryption = {
  kty: "OKP",
  crv: "X25519",
  x: publicKeyEncBase58,
};

// console.log("JWK Encryption Key:", jwkEncryption);

dvvRouter.use(express.json());
dvvRouter.use(express.urlencoded({ extended: true }));

let presentationDefinitionParam;
let vpRequestJWT = "";

// make our own did:key based on our jwks
// did-key-format := did:key:MULTIBASE(base58-btc, MULTICODEC(public-key-type, raw-public-key-bytes))
const jwk = pemToJWK(publicKey, "public");
// console.log("*******************");
// console.log(jwk);
// console.log("*******************");

const did = `did:web:${ngrok.replace("https://", "")}:dvv`; //util.createDid(jwk);
// console.log(`my did:web DID is ${did}`);

// Define your /makeVP endpoint handling logic
dvvRouter.get("/makeVP", async (req, res) => {
  try {
    const uuid = uuidv4();
    const stateParam = uuidv4();
    const nonce = generateNonce(16);
    let request_uri = ngrok + "/dvv/vpRequest";
    const response_uri = ngrok + "/dvv/direct_post";
    vpRequestJWT = buildVpRequestJwt(
      stateParam,
      nonce,
      did,
      uuid,
      response_uri,
      jwk
    );
    const vpRequest = buildVP(did, request_uri);
    res.json({ vpRequest: vpRequest });
  } catch (err) {
    console.log(err);
    const responseMessage = "Hello, this is the /test endpoint!";
    res.json({ message: responseMessage });
  }
});

// Define your /vpRequest endpoint handling logic
dvvRouter.get("/vpRequest", async (req, res) => {
  console.log("VPRequest called Will send JWT");
  console.log(vpRequestJWT);
  res.send(vpRequestJWT);
});

// this is not called in did:web resolution, however it is called in classic OIDC4VP
// NOT Necessary
dvvRouter.get(["/jwks"], async (req, res) => {
  console.log("Requested URL:", req.url);
  const response = {
    keys: [{ ...jwk, use: "sig", kid: `aegean#authentication-key` }],
  };
  console.log(JSON.stringify(response, undefined, 2));
  res.type("application/json").send(response);
});

// the /did.json is called based on the did:web spec to get the 
// public jwks of the verifier
dvvRouter.get(["/.well-known/did.json", "/did.json"], async (req, res) => {
  console.log("Requested URL:", req.url);
  const response = {
    "@context": "https://www.w3.org/ns/did/v1",
    id: `${did}`,
    verificationMethod: [
      {
        id: `aegean#authentication-key`,
        type: "JsonWebKey2020",
        controller: `${did}`,
        publicKeyJwk: { ...jwk },
      },
      {
        ...jwkEncryption,
        id: `aegean#enc-key`,
        type: "X25519KeyAgreementKey2019",
        controller: `${did}`,
      },
    ],
    authentication: [`aegean#authentication-key`],
    keyAgreement: [`aegean#enc-key`],
  };
  // console.log(JSON.stringify(response, undefined, 2));
  res.type("application/json").send(response);
});

// endpoint the receives the sd-jwt response from the wallet
dvvRouter.post("/direct_post", async (req, res) => {
  console.log("dvv/direct_post VP is below!");
  // for (const [fieldName, fieldValue] of Object.entries(req.body)) {
  //   console.log(`***************************>>>>>${fieldName}: ${fieldValue}`);
  // }
  let response = req.body["response"];
  let state = req.body["state"];
  console.log(response);
  // console.log(decryptJWE(response, privateKey));
  let userData = await decryptJWE(response, privateKey)
  console.log("USER Data")
  console.log(userData)

  res.sendStatus(200);
});

//UTILS TODO move to a different file
// builds the VP request
function buildVpRequestJwt(state, nonce, client_id, id, redirect_uri, jwks) {
  let jwtPayload = {
    aud: "https://self-issued.me/v2", //this value is important based on SIOPv2. https://self-issued.me/v2 has specific semantics
    exp: Math.floor(Date.now() / 1000) + 60,
    nbf: Math.floor(Date.now() / 1000),
    iss: ngrok + "/dvv",
    client_id: client_id,
    client_metadata: {
      jwks: {
        keys: [
          { ...jwk, kid: `aegean#authentication-key`, use: "sig" },
          { ...jwk, kid: `aegean#authentication-key`, use: "keyAgreement" }, //key to encrypt the sd-jwt response
        ],
      },
      vp_formats: {
        kb_jwt: {
          alg: ["ES256"],
        },
        sd_jwt: {
          alg: ["ES384"],
        },
      },
    },
    presentation_definition: {
      id: "",
      format: {
        sd_jwt: {
          alg: ["ES384"],
        },
        kb_jwt: {
          alg: ["ES256"],
        },
      },
      input_descriptors: [
        {
          id: "given_name",
          constraints: {
            fields: [
              {
                path: ["$.iss"],
                filter: {
                  const: "fi.dvv.digiid",
                },
              },
              {
                path: ["$.credentialSubject.given_name"],
                filter: {
                  type: "string",
                },
              },
            ],
          },
        },
        {
          id: "family_name",
          constraints: {
            fields: [
              {
                path: ["$.iss"],
                filter: {
                  const: "fi.dvv.digiid",
                },
              },
              {
                path: ["$.credentialSubject.family_name"],
                filter: {
                  type: "string",
                },
              },
            ],
          },
        },
        {
          id: "birth_date",
          constraints: {
            fields: [
              {
                path: ["$.iss"],
                filter: {
                  const: "fi.dvv.digiid",
                },
              },
              {
                path: ["$.credentialSubject.birth_date"],
                filter: {
                  type: "string",
                },
              },
            ],
          },
        },
        {
          id: "age_over_15",
          constraints: {
            fields: [
              {
                path: ["$.iss"],
                filter: {
                  const: "fi.dvv.digiid",
                },
              },
              {
                path: ["$.credentialSubject.age_over_15"],
                filter: {
                  type: "boolean",
                },
              },
            ],
          },
        },
        {
          id: "age_over_18",
          constraints: {
            fields: [
              {
                path: ["$.iss"],
                filter: {
                  const: "fi.dvv.digiid",
                },
              },
              {
                path: ["$.credentialSubject.age_over_18"],
                filter: {
                  type: "boolean",
                },
              },
            ],
          },
        },
        {
          id: "age_over_20",
          constraints: {
            fields: [
              {
                path: ["$.iss"],
                filter: {
                  const: "fi.dvv.digiid",
                },
              },
              {
                path: ["$.credentialSubject.age_over_20"],
                filter: {
                  type: "boolean",
                },
              },
            ],
          },
        },
        {
          id: "gender",
          constraints: {
            fields: [
              {
                path: ["$.iss"],
                filter: {
                  const: "fi.dvv.digiid",
                },
              },
              {
                path: ["$.credentialSubject.gender"],
                filter: {
                  type: "integer",
                  enum: [0, 1, 2, 9],
                },
              },
            ],
          },
        },
        {
          id: "nationality",
          constraints: {
            fields: [
              {
                path: ["$.iss"],
                filter: {
                  const: "fi.dvv.digiid",
                },
              },
              {
                path: ["$.credentialSubject.nationality"],
                filter: {
                  type: "string",
                },
              },
            ],
          },
        },
        {
          id: "personal_identity_code",
          constraints: {
            fields: [
              {
                path: ["$.iss"],
                filter: {
                  const: "fi.dvv.digiid",
                },
              },
              {
                path: ["$.credentialSubject.personal_identity_code"],
                filter: {
                  type: "string",
                },
              },
            ],
          },
        },
        {
          id: "unique_id",
          constraints: {
            fields: [
              {
                path: ["$.iss"],
                filter: {
                  const: "fi.dvv.digiid",
                },
              },
              {
                path: ["$.credentialSubject.unique_id"],
                filter: {
                  type: "string",
                },
              },
            ],
          },
        },
      ],
    },
    redirect_uri: redirect_uri,
    response_type: "vp_token",
    response_mode: "direct_post.jwt",
    scope: "openid",
    nonce: nonce,
    state: state,
  };

  const header = {
    alg: "ES384",
    kid: `aegean#authentication-key`, //this kid needs to be resolvable from the did.json endpoint
  };

  const token = jwt.sign(jwtPayload, privateKey, {
    algorithm: "ES384",
    noTimestamp: true,
    header,
  });
  return token;
}

//oidc endpoint not called for did:web
dvvRouter.get(["/", "/jwks"], (req, res) => {
  console.log("DVV ROUTE ./jwks CALLED!!!!!!");
  res.json({ keys: [{ ...jwk, kid: `${did}#authentication-key` }] });
});

function buildVP(
  client_id, //did
  request_uri
) {
  let result =
    "openid4vp://?client_id=" +
    encodeURIComponent(client_id) +
    "&request_uri=" +
    encodeURIComponent(request_uri);
  return result;
}

function generateNonce(length) {
  return crypto.randomBytes(length).toString("hex");
}

function pemToJWK(pem, keyType) {
  const key = crypto.createPublicKey(pem);
  const { x, y } = key.export({ format: "jwk", publicKey: true });
  const jwk = { kty: "EC", crv: "P-384", x, y };

  if (keyType === "private") {
    const privateKey = crypto.createPrivateKey(pem);
    const { d } = privateKey.export({ format: "jwk", privateKey: true });
    jwk.d = d;
  }

  return jwk;
}

async function decryptJWE(jweToken, privateKeyPEM) {
  try {
    const privateKey = crypto.createPrivateKey(privateKeyPEM);

    // Decrypt the JWE using the private key
    const decryptedPayload = await jose.jwtDecrypt(jweToken, privateKey);
    // console.log(decryptedPayload);
    let presentation_submission =
      decryptedPayload.payload.presentation_submission;
    let disclosures = parseVP(decryptedPayload.payload.vp_token);
    console.log(`diclosures in the VP found`);
    console.log(disclosures);
    return disclosures;
  } catch (error) {
    console.error("Error decrypting JWE:", error.message);
    throw error;
  }
}

/*
An SD-JWT is composed of the following:
the Issuer-signed JWT
The Disclosures
optionally a Key Binding JWT
The serialized format for the SD-JWT is the concatenation of each part delineated with a single tilde ('~') character as follows:
<JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~<optional KB-JWT>

*/
function parseVP(vp_token) {
  let vpPartsArray = vp_token.split(".");
  let disclosuresPart = vpPartsArray[2]; //this is the actual sd-jdt from the vpToken

  let disclosuresArray = disclosuresPart.split("~").slice(1, -1); //get all elements apart form the first and last one
  // console.log(disclosuresArray);
  let decodedDisclosuresArray = disclosuresArray.map((element) => {
    return base64urlDecode(element);
  });
  return decodedDisclosuresArray;
}
const base64urlDecode = (input) => {
  // Convert base64url to base64 by adding padding characters
  const base64 = input
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(input.length + ((4 - (input.length % 4)) % 4), "=");
  // Decode base64
  const utf8String = atob(base64);
  // Convert UTF-8 string to byte array
  const bytes = new Uint8Array(utf8String.length);
  for (let i = 0; i < utf8String.length; i++) {
    bytes[i] = utf8String.charCodeAt(i);
  }
  let decodedString = new TextDecoder().decode(bytes);
  return JSON.parse(decodedString);
};

export default dvvRouter;
