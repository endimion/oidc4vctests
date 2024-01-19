// Now you can use import syntax
import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";
import { v4 as uuidv4 } from "uuid";
import jwt from "jsonwebtoken";
import fs from "fs";
import jose from "node-jose";
import { Resolver } from "did-resolver";
import { getResolver } from "@cef-ebsi/key-did-resolver";
import jwkToPem from "jwk-to-pem";

const app = express();

const port = 3000; // You can change the port as needed
const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
// Read the public key from PEM file
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");

const ngrok =
  "https://8d15-2a02-587-2809-9100-e86a-b83f-360-691b.ngrok-free.app";

// Convert PEM to JWK
const keystore = jose.JWK.createKeyStore();
keystore.add(privateKey, "pem").then(function (_) {
  const jwks = keystore.toJSON(true);
  console.log(JSON.stringify(jwks, null, 4));
});

// Extract crv, x, and y

const jwks = [
  {
    alg: "P-256", //"ES256",
    kty: "EC",
    use: "sig",
    kid: "a1580646-1c0b-47f2-bb55-cac0c40a0601",
    crv: "P-256",
    x: "7ymGipkLd1oxRGYCIat84OqzuPfL0YoL-rYAoKqPjxk",
    y: "EJLD8Db88LP2sd2HClVkZrdxl0yipmGUfKF85IfUU6Q",
  },
];
// Middleware to parse JSON requests
app.use(express.json());
// Middleware to parse urlencoded data
app.use(express.urlencoded({ extended: true }));

//this could store the jwts indexed by the session but for now
// just store the single definition we have
let jwtToken = "";

// Controller for the "/test" endpoint
app.get("/makeVP", async (req, res) => {
  try {
    // Get the presentation_definition parameter
    const presentationDefinitionParam = {
      id: "vp token example",
      format: {
        jwt_vc: { alg: ["ES256"] },
        jwt_vp: { alg: +["ES256"] },
      },
      input_descriptors: [
        {
          id: "id card credential",

          constraints: {
            fields: [
              {
                path: ["$.type"],
                filter: {
                  type: "array",
                  contains: {
                    const: "VerifiablePortableDocumentA1",
                  },
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
    const redirect_uri = ngrok + "/direct_post";

    const nonce = generateNonce(16);

    jwtToken = buildJwt(
      presentationDefinitionParam.input_descriptors,
      stateParam,
      nonce,
      redirect_uri,
      uuid,
      redirect_uri
    );

    let request_uri = ngrok + "/vpRequest";
    const responseMessage = buildVP(
      redirect_uri,
      redirect_uri,
      request_uri,
      stateParam,
      nonce,
      encodeURIComponent(JSON.stringify(presentationDefinitionParam))
    );

    res.json({ vpRequest: responseMessage });
  } catch (err) {
    console.log(err);
    const responseMessage = "Hello, this is the /test endpoint!";
    res.json({ message: responseMessage });
  }
});

// JWKS endpoint to serve the keys
app.get(["/", "/jwks"], (req, res) => {
  res.json({ keys: jwks });
});

app.get("/vpRequest", async (req, res) => {
  res.type("text/plain").send(jwtToken);
});

app.post("/direct_post", async (req, res) => {
  console.log("HEEEYYYY THE PRESENTED VP is below!");
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
    let innerJwk= didDoc.didDocument.verificationMethod[0].publicKeyJwk
    // console.log("INNER JWK")
    // console.log(innerJwk)
    const innerPem = jwkToPem(innerJwk);
    let decodedVC = jwt.verify(vc, innerPem, { ignoreNotBefore: true });
    console.log(decodedVC);
  });

  res.sendStatus(200);
});

function buildJwt(inputDescriptors, state, nonce, client_id, id, redirect_uri) {
  let jwtPayload = {
    aud: ngrok,
    client_id: client_id,
    exp: Math.floor(Date.now() / 1000) + 60 * 60,
    iss: ngrok,
    nonce: nonce,
    presentation_definition: {
      format: {
        jwt_vc: {
          alg: ["ES256"],
        },
        jwt_vp: {
          alg: ["ES256"],
        },
      },
      id: id,
      input_descriptors: inputDescriptors,
    },
    // response_uri: redirect_uri,
    redirect_uri: redirect_uri,
    response_mode: "direct_post",
    response_type: "vp_token",
    scope: "openid",
    state: state,
  };

  const header = {
    alg: "ES256",
    typ: "JWT",
    kid: "a1580646-1c0b-47f2-bb55-cac0c40a0601",
  };

  const token = jwt.sign(jwtPayload, privateKey, {
    algorithm: "ES256",
    header,
  });

  return token;
}

function generateNonce(length) {
  return crypto.randomBytes(length).toString("hex");
}

function buildVP(
  client_id,
  redirect_uri,
  request_uri,
  state,
  nonce,
  presentation_definition
) {
  let result =
    "openid://?client_id=" +
    encodeURIComponent(client_id) +
    "&response_type=vp_token" +
    "&scope=openid" +
    // "&response_uri="+
    // encodeURIComponent(redirect_uri) +
    "&request_uri=" +
    request_uri +
    "&redirect_uri=" +
    encodeURIComponent(redirect_uri) +
    "&response_mode=direct_post" +
    "&state=" +
    state +
    "&nonce=" +
    nonce +
    "&presentation_definition=" +
    presentation_definition;

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

function fromP521KeyToJWK(publicKeyHex) {
  let pkey = publicKeyHex.split("#")[0];
  console.log("public key");
  console.log(pkey);
  // The encoded public key

  // Base64Url decode
  const decodedPublicKeyBinary = atob(
    pkey.replace(/-/g, "+").replace(/_/g, "/")
  );

  // Convert binary data to hexadecimal
  const decodedPublicKeyHex = Array.from(decodedPublicKeyBinary)
    .map((byte) => byte.charCodeAt(0).toString(16).padStart(2, "0"))
    .join("");

  // Output the result
  const cleanedHex = decodedPublicKeyHex.replace("#", "");

  // Convert the cleaned hex to Buffer
  const publicKeyBuffer = Buffer.from(cleanedHex, "hex");
  console.log(publicKeyBuffer.length);
  // Check if the buffer length is as expected (132 bytes for P-521)
  //   if (publicKeyBuffer.length !== 132) {
  //     throw new Error("Invalid P-521 public key length");
  //   }

  // Convert the Buffer to a JSON Web Key (JWK)
  const jwk = {
    kty: "EC",
    crv: "P-521",
    x: publicKeyBuffer.slice(0, 66).toString("base64url"),
    y: publicKeyBuffer.slice(66).toString("base64url"),
  };

  return jwk;
}

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
