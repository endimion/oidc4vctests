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

const dvvRouter = express.Router();

const ngrok = process.env.NGROK;

const privateKey = fs.readFileSync("./private_key_384.pem", "utf-8");
const publicKey = fs.readFileSync("./public_key_384.pem", "utf-8");

dvvRouter.use(express.json());
dvvRouter.use(express.urlencoded({ extended: true }));

let presentationDefinitionParam;
let jwtToken = "";

// make our own did:key based on our jwks
// did-key-format := did:key:MULTIBASE(base58-btc, MULTICODEC(public-key-type, raw-public-key-bytes))
const jwk = pemToJWK(publicKey, "public");
console.log(jwk);

const did = `did:web:${ngrok.replace("https://", "")}:dvv:testKey`; //util.createDid(jwk);
console.log(`my did:web DID is ${did}`);

// Define your /makeVP endpoint handling logic
dvvRouter.get("/makeVP", async (req, res) => {
  try {
    // Get the presentation_definition parameter
    presentationDefinitionParam = {
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
      ],
    };

    const uuid = uuidv4();

    //url.searchParams.get("presentation_definition");
    const stateParam = uuidv4();
    const nonce = generateNonce(16);

    let request_uri = ngrok + "/dvv/vpRequest";
    const response_uri = ngrok + "/dvv/direct_post";

    /*
     inputDescriptors,
  state,
  nonce,
  client_id,
  id,
  redirect_uri,
  jwks
    */
    jwtToken = buildJwt(
      presentationDefinitionParam.input_descriptors,
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
  console.log(jwtToken);
  res.send(jwtToken);
});

dvvRouter.get("/presentation_definition", async (req, res) => {
  console.log("CALLED presentation_definition");
  res.type("application/json").send(presentationDefinitionParam);
});

// this is the did:web endpoint to get the did document
dvvRouter.get("/testKey/did.json", async (req, res) => {
  console.log("CALLED /dvv/testkey");
  res.type("application/json").send({
    id: `${did}`,
    verificationMethod: [
      {
        id: `${did}#authentication-key`,
        type: "JsonWebKey2020",
        controller: `${did}`,
        publicKeyJwk: jwk,
      },
    ],
    authentication: [`${did}#authentication-key`],
  });
});

dvvRouter.post("/direct_post", async (req, res) => {
  console.log("dvv/direct_post VP is below!");
  // for (const [fieldName, fieldValue] of Object.entries(req.body)) {
  //   console.log(`${fieldName}: ${fieldValue}`);
  // }
  let vp = req.body["vp_token"];
  let state = req.body["state"]; //the state, i.e. request id
  console.log(vp);
  let header = getHeaderFromToken(vp);
  // console.log(header);
  let kid = header.kid;
  let issuerJwk = header.jwk;
  if (kid.includes("did:key")) {
    const keyResolver = getResolver();
    const didResolver = new Resolver(keyResolver);
    const doc = await didResolver.resolve(kid);
    // console.log(doc);
  }
  const pem = jwkToPem(issuerJwk);
  const decoded = jwt.verify(vp, pem, { ignoreNotBefore: true });
  //console.log(decoded)
  const vcs = decoded.vp.verifiableCredential;
  let vcHeader;
  let vcKid;
  vcs.forEach(async (vc) => {
    vcHeader = getHeaderFromToken(vc);
    console.log(vcHeader);
    vcKid = vcHeader.kid;
    let didKey = vcKid.split("#")[0];
    const keyResolver = getResolver();
    const didResolver = new Resolver(keyResolver);
    let didDoc = await didResolver.resolve(didKey); //this is a multibase encoded string
    let innerJwk = didDoc.didDocument.verificationMethod[0].publicKeyJwk;
    // console.log("INNER JWK")
    // console.log(innerJwk)
    const innerPem = jwkToPem(innerJwk);
    let decodedVC = jwt.verify(vc, innerPem, { ignoreNotBefore: true });
    console.log(decodedVC);
  });

  res.sendStatus(200);
});

//UTILS TODO move to a different file
function buildJwt(
  inputDescriptors,
  state,
  nonce,
  client_id,
  id,
  redirect_uri,
  jwks
) {
  let jwtPayload = {
    aud: ngrok, //this doesnt seem to matter mock value...
    //the did of the client is added as client_id,
    //a DID web was added here. To resolve a did:web you go to did:web:test.id.cloud.dvv.fi:test-rp-ui ->>  https://test.id.cloud.dvv.fi/test-rp-ui/did.json
    exp: Math.floor(Date.now() / 1000) + 60 * 60,
    nbf: Math.floor(Date.now() / 1000),

    client_id: client_id,
    client_metadata: {
      jwks: {
        keys: [jwks], //the jwks keys (assumin that are used to sign the jwt?)
        // missing "use": "keyAgreement",
        //missing  "kid": "QnE33F6_5oCP5dQ61Tufyj5GsSmBDAomAsimbxW3RyQ",
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
      input_descriptors: inputDescriptors,
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

  return token;
}

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
