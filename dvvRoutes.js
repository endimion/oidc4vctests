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
    //url.searchParams.get("presentation_definition");
    const stateParam = uuidv4();
    const nonce = generateNonce(16);
    let request_uri = ngrok + "/dvv/vpRequest";
    const response_uri = ngrok + "/dvv/direct_post";

    //buildVpRequestJwt(state, nonce, client_id, id, redirect_uri, jwks)
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

// this is the did:web endpoint to get the did document
dvvRouter.get(["/jwks"], async (req, res) => {
  console.log("CALLED /jwks");
  console.log("Requested URL:", req.url);
  const response = {
    keys: [{ ...jwk, use: "sig", kid: `aegean#authentication-key` }],
  };

  console.log(JSON.stringify(response, undefined, 2));
  res.type("application/json").send(response);
});

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
        // controller: `${ngrok}`,
      },
    ],
    authentication: [`aegean#authentication-key`],
    keyAgreement: [`aegean#enc-key`],
  };
  /*
    
    */

  console.log(JSON.stringify(response, undefined, 2));
  res.type("application/json").send(response);
});

dvvRouter.post("/direct_post", async (req, res) => {
  console.log("dvv/direct_post VP is below!");
  for (const [fieldName, fieldValue] of Object.entries(req.body)) {
    console.log(`${fieldName}: ${fieldValue}`);
  }
  let response = req.body["response"];
  let state = req.body["state"];
  console.log(response);
  console.log(decryptJWE(response, privateKey));

  res.sendStatus(200);
});

//UTILS TODO move to a different file
function buildVpRequestJwt(state, nonce, client_id, id, redirect_uri, jwks) {
  let jwtPayload = {
    aud: "https://self-issued.me/v2", //aud: ngrok, //ngrok this doesnt seem to matter mock value...
    exp: Math.floor(Date.now() / 1000) + 60 ,
    nbf: Math.floor(Date.now() / 1000),
    iss: ngrok + "/dvv",
    client_id: client_id,
    client_metadata: {
      jwks: {
        keys: [
          { ...jwk, kid: `aegean#authentication-key`, use: "sig" },
          { ...jwk, kid: `aegean#authentication-key`, use: "keyAgreement" },
          // {
          //   ...jwkEncryption,
          //   use: "keyAgreement",
          //   kid: `aegean#enc-key`,

          //   // controller: `${ngrok}`,
          // },
          // {
          //   crv: "P-256",
          //   kid: "7c1ec871-29c1-4c23-ac62-7960d23aef05",
          //   kty: "EC",
          //   use: "keyAgreement",
          //   x: "mPBqJh0LpnjSbhyvZMVzeI-rjBmu9xplm5u0pssmYko",
          //   y: "BF6IrtN8BG6E97nUQ9awjHCQ9sXosmO_6P09HLamxmc",
          // },

          // {
          //   crv: "P-384",
          //   kid: "44969b4a-48d6-442a-98ac-34bff24f5da3",
          //   kty: "EC",
          //   use: "sig",
          //   x: "PjAakaRoG2tOfmFVRnfReU9SBqXF2x2n5XkKb-NAL5bjUvpJnwXPXzLOKUxU2zmt",
          //   y: "9R-Xm3Frz0oPpya6VyD9PLE7teoMQ0fLXRTEMcohW5rZzMzmwRSonar1-y51xudq",
          // },
          // {
          //   crv: "P-384",
          //   kid: "209553f2-26ba-4b8d-b578-557488a3a952",
          //   kty: "EC",
          //   use: "keyAgreement",
          //   x: "AaCSSGVmX_GwiMsIgqeas5nHiMdRa-a2_phqwZNjtugqjWCQRVAaV8ipSeAFXGs9",
          //   y: "RTCwd4cZeQoG-tAVTl-WCpX0YFXCPArjxNz35c41ql4IoYT1sJz3efxj-0y8tF6U",
          // },
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
      format: {
        kb_jwt: {
          alg: ["ES256"],
        },
        sd_jwt: {
          alg: ["ES384"],
        },
      },
      id: "56e35ba0-fa9b-4bcc-a67f-ab82187ae401",
      input_descriptors: [
        {
          constraints: {
            fields: [
              {
                filter: {
                  const: "fi.dvv.digiid",
                },
                path: ["$.iss"],
              },
              {
                filter: {
                  type: "string",
                },
                path: ["$.credentialSubject.given_name"],
              },
            ],
          },
          id: "given_name",
        },
        {
          constraints: {
            fields: [
              {
                filter: {
                  const: "fi.dvv.digiid",
                },
                path: ["$.iss"],
              },
              {
                filter: {
                  type: "string",
                },
                path: ["$.credentialSubject.family_name"],
              },
            ],
          },
          id: "family_name",
        },
        {
          constraints: {
            fields: [
              {
                filter: {
                  const: "fi.dvv.digiid",
                },
                path: ["$.iss"],
              },
              {
                filter: {
                  type: "string",
                },
                path: ["$.credentialSubject.birth_date"],
              },
            ],
          },
          id: "birth_date",
        },
        {
          constraints: {
            fields: [
              {
                filter: {
                  const: "fi.dvv.digiid",
                },
                path: ["$.iss"],
              },
              {
                filter: {
                  enum: [0, 1, 2, 9],
                  type: "integer",
                },
                path: ["$.credentialSubject.gender"],
              },
            ],
          },
          id: "gender",
        },
        {
          constraints: {
            fields: [
              {
                filter: {
                  const: "fi.dvv.digiid",
                },
                path: ["$.iss"],
              },
              {
                filter: {
                  type: "string",
                },
                path: ["$.credentialSubject.nationality"],
              },
            ],
          },
          id: "nationality",
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
    kid: `aegean#authentication-key`,
  };

  // const token = jwt.sign(jwtPayload, privateKey, {
  //   algorithm: "ES384",
  //   header,
  // });
  const token = jwt.sign(jwtPayload, privateKey, {
    algorithm: "ES384",
    noTimestamp: true,
    header,
  });

  // console.log("jwt generated" + token)
  return token;
}

dvvRouter.get(["/", "/jwks"], (req, res) => {
  console.log("DVV ROUTE ./jwks CALLED!!!!!!");
  // console.log(jwk);
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

function getHeaderFromToken(token) {
  const decodedToken = jwt.decode(token, {
    complete: true,
  });

  if (!decodedToken) {
    throw new Parse.Error(
      Parse.Error.OBJECT_NOT_FOUND,
      `provided token does not decode as JWT`
    );
  }

  return decodedToken.header;
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
    // Return the decrypted payload
    console.log(decryptedPayload)
    return decryptedPayload.vp_token;
  } catch (error) {
    console.error("Error decrypting JWE:", error.message);
    throw error;
  }
}

export default dvvRouter;
