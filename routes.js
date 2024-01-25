// routes.js
import express from "express";
import { v4 as uuidv4 } from "uuid";
import jwt from "jsonwebtoken";
import fs from "fs";
import jwkToPem from "jwk-to-pem";
import { Resolver } from "did-resolver";
import { getResolver } from "@cef-ebsi/key-did-resolver";
import crypto from "crypto";

const router = express.Router();

const ngrok = process.env.NGROK;
const privateKey = fs.readFileSync("./private-key.pem", "utf-8");

router.use(express.json());
router.use(express.urlencoded({ extended: true }));

let presentationDefinitionParam;
let jwtToken = "";

// Define your /makeVP endpoint handling logic
router.get("/makeVP", async (req, res) => {
  try {
    // Get the presentation_definition parameter
    presentationDefinitionParam = {
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
    //passport

    const uuid = uuidv4();

    //url.searchParams.get("presentation_definition");
    const stateParam = uuidv4();
    const nonce = generateNonce(16);

    let request_uri = ngrok + "/vpRequest";
    const response_uri = ngrok + "/direct_post";

    jwtToken = buildJwt(
      presentationDefinitionParam.input_descriptors,
      stateParam,
      nonce,
      ngrok,
      uuid,
      response_uri,
      request_uri
    );

    const vpRequest = buildVP(
      ngrok,
      response_uri,
      request_uri,
      stateParam,
      nonce,
      encodeURIComponent(JSON.stringify(presentationDefinitionParam))
    );

    res.json({ vpRequest: vpRequest });
  } catch (err) {
    console.log(err);
    const responseMessage = "Hello, this is the /test endpoint!";
    res.json({ message: responseMessage });
  }
});

// Define your /vpRequest endpoint handling logic
router.get("/vpRequest", async (req, res) => {
  console.log("VPRequest called Will send JWT");
  // console.log(jwtToken);
  res.type("text/plain").send(jwtToken);
});

router.get("/presentation_definition", async (req, res) => {
  console.log("CALLED presentation_definition");
  res.type("application/json").send(presentationDefinitionParam);
});

router.post("/direct_post", async (req, res) => {
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
  request_uri
) {
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
    // request_uri: request_uri,
    // redirect_uri: redirect_uri,
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

function buildVP(
  client_id,
  redirect_uri,
  request_uri,
  state,
  nonce,
  presentation_definition
) {
  //with iGrant.io if you do not include the redirect_uri, the request to the request_uri is never made... and the flow fails
  // also if you do not include presentation_definition in the request, the igrant.io wallet fails to parse the qr code.
  //even if you include presentation_definition_uri
  let result =
    "openid://?client_id=" +
    encodeURIComponent(client_id) +
    "&response_type=vp_token" +
    "&scope=openid" +
    "&redirect_uri=" +
    encodeURIComponent(redirect_uri) +
    "&request_uri=" +
    encodeURIComponent(request_uri) +
    "&response_uri=" +
    encodeURIComponent(redirect_uri) +
    "&response_mode=direct_post" +
    "&state=" +
    state +
    "&nonce=" +
    nonce +
    // "&presentation_definition_uri="+ngrok+"/presentation_definition"
    // +
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
function generateNonce(length) {
  return crypto.randomBytes(length).toString("hex");
}

export default router;
