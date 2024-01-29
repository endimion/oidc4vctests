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

console.log("JWK Encryption Key:", jwkEncryption);

dvvRouter.use(express.json());
dvvRouter.use(express.urlencoded({ extended: true }));

let presentationDefinitionParam;
let vpRequestJWT = "";

// make our own did:key based on our jwks
// did-key-format := did:key:MULTIBASE(base58-btc, MULTICODEC(public-key-type, raw-public-key-bytes))
const jwk = pemToJWK(publicKey, "public");
console.log("*******************");
console.log(jwk);
console.log("*******************");

const did = `did:web:${ngrok.replace("https://", "")}:dvv:testKey`; //util.createDid(jwk);
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

// dvvRouter.get("/presentation_definition", async (req, res) => {
//   console.log("CALLED presentation_definition");
//   res.type("application/json").send(presentationDefinitionParam);
// });

// this is the did:web endpoint to get the did document
dvvRouter.get(
  ["/testKey/did.json", "/testkey/.well-known/did.json"],
  async (req, res) => {
    console.log("CALLED /dvv/testkey");
    const response = {
      id: `${did}`,
      verificationMethod: [
        {
          id: `${did}#authentication-key`,
          type: "JsonWebKey2020",
          // controller: `${ngrok}`,
          publicKeyJwk: { ...jwk },
        },
        {
          ...jwkEncryption,
          id: `${did}#enc-key`,
          type: "X25519KeyAgreementKey2019",
          // controller: `${ngrok}`,
        },
      ],
      authentication: [`${did}#authentication-key`],
      keyAgreement: [`${did}#enc-key`],
    };
    console.log(response);
    res.type("application/json").send(response);
  }
);

dvvRouter.post("/direct_post", async (req, res) => {
  console.log("dvv/direct_post VP is below!");
  for (const [fieldName, fieldValue] of Object.entries(req.body)) {
    console.log(`${fieldName}: ${fieldValue}`);
  }
  let response = req.body["response"];
  let state = req.body["state"];
  console.log(response);

  res.sendStatus(200);
});

//UTILS TODO move to a different file
function buildVpRequestJwt(state, nonce, client_id, id, redirect_uri, jwks) {
  let jwtPayload = {
    aud: "https://self-issued.me/v2", //aud: ngrok, //ngrok this doesnt seem to matter mock value...
    //the did of the client is added as client_id,
    //a DID web was added here. To resolve a did:web you go to did:web:test.id.cloud.dvv.fi:test-rp-ui ->>  https://test.id.cloud.dvv.fi/test-rp-ui/did.json
    exp: Math.floor(Date.now() / 1000) + 60 * 60,
    nbf: Math.floor(Date.now() / 1000),
    iss: ngrok + "/dvv",

    client_id: client_id,
    client_metadata: {
      jwks: {
        keys: [{ ...jwk, kid: `${did}#authentication-key` }],
      },
      vp_formats: {
        sd_jwt: {
          alg: ["ES384"],
        },
        kb_jwt: {
          alg: ["ES256"],
        },
      },
    },
    presentation_definition: {
      format: {
        sd_jwt: {
          alg: ["ES384"],
        },
        kb_jwt: {
          alg: ["ES256"],
        },
      },
      id: id,
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
    kid: `${did}#authentication-key`,
  };

  const token = jwt.sign(jwtPayload, privateKey, {
    algorithm: "ES384",
    header,
  });

  // console.log("jwt generated" + token)
  return token;
}

//TODO this is missing the aud that should resolve to the issuer to fetch the jwks of the issuer of the vpRequest (jwt)
dvvRouter.get(["/", "/jwks"], (req, res) => {
  console.log("DVV ROUTE ./jwks CALLED!!!!!!");
  console.log(jwk);
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

export default dvvRouter;
