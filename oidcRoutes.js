// routes.js
import express from "express";
import fs from "fs";
import jose from "node-jose";

const oidcRouter = express.Router();

 
const privateKey = fs.readFileSync("./private-key.pem", "utf-8");
const publicKeyPem = fs.readFileSync("./public-key.pem", "utf-8");
// Read the public key from PEM file
// Convert PEM to JWK
const keystore = jose.JWK.createKeyStore();
keystore.add(privateKey, "pem").then(function (_) {
  const jwks = keystore.toJSON(true);
//   console.log(JSON.stringify(jwks, null, 4));
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

oidcRouter.use(express.json());
oidcRouter.use(express.urlencoded({ extended: true }));

 
oidcRouter.get(["/", "/jwks"], (req, res) => {
  console.log("ROUTE ./jwks CALLED!!!!!!")
  res.json({ keys: jwks });
});
oidcRouter.get("/.well-known/openid-credential-issuer", async (req, res) => {
  console.log(".well-known/openid-credential-issuer called Will send");

  res.type("text/plain").send({
    credential_issuer: "https://sweden-eudi-wallet.igrant.io",
    authorization_server: "https://sweden-eudi-wallet.igrant.io",
    credential_endpoint: "https://sweden-eudi-wallet.igrant.io/credential",
    deferred_credential_endpoint:
      "https://sweden-eudi-wallet.igrant.io/credential_deferred",
    display: {
      name: "University of the Aegean",
      location: "Greece",
      locale: "en-GB",
      cover: {
        url: "https://storage.googleapis.com/data4diabetes/cover.jpeg",
        alt_text: "University of the Aegean",
      },
      logo: {
        url: "https://storage.googleapis.com/data4diabetes/sweden.jpg",
        alt_text: "University of the Aegean",
      },
      description:
        "For queries about how we are managing your data please contact the Data Protection Officer.",
    },
    credentials_supported: [
      {
        format: "jwt_vc",
        types: [
          "VerifiableCredential",
          "VerifiableAttestation",
          "CTWalletSameDeferred",
        ],
        trust_framework: {
          name: "ebsi",
          type: "Accreditation",
          uri: "TIR link towards accreditation",
        },
        display: [{ name: "Conformance tests deferred", locale: "en-GB" }],
      },
      {
        format: "jwt_vc",
        types: [
          "VerifiableCredential",
          "VerifiableAttestation",
          "CTWalletSamePreAuthorised",
        ],
        trust_framework: {
          name: "ebsi",
          type: "Accreditation",
          uri: "TIR link towards accreditation",
        },
        display: [
          { name: "Conformance tests pre-authorised", locale: "en-GB" },
        ],
      },
      {
        format: "jwt_vc",
        types: [
          "VerifiableCredential",
          "VerifiableAttestation",
          "CTWalletSameInTime",
        ],
        trust_framework: {
          name: "ebsi",
          type: "Accreditation",
          uri: "TIR link towards accreditation",
        },
        display: [{ name: "Conformance tests in-time", locale: "en-GB" }],
      },
      {
        format: "jwt_vc",
        types: ["VerifiableCredential", "VerifiableAttestation", "CTRevocable"],
        trust_framework: {
          name: "ebsi",
          type: "Accreditation",
          uri: "TIR link towards accreditation",
        },
        display: [{ name: "Conformance test revocation", locale: "en-GB" }],
      },
      {
        format: "jwt_vc",
        types: [
          "VerifiableCredential",
          "VerifiableAttestation",
          "VerifiableAuthorisationToOnboard",
        ],
        trust_framework: {
          name: "ebsi",
          type: "Accreditation",
          uri: "TIR link towards accreditation",
        },
        display: [
          { name: "Verifiable Authorisation to onboard", locale: "en-GB" },
        ],
      },
      {
        format: "jwt_vc",
        types: [
          "VerifiableCredential",
          "VerifiableAttestation",
          "VerifiableAccreditation",
          "VerifiableAccreditationToAttest",
        ],
        trust_framework: {
          name: "ebsi",
          type: "Accreditation",
          uri: "TIR link towards accreditation",
        },
        display: [
          { name: "Verifiable Accreditation to attest", locale: "en-GB" },
        ],
      },
      {
        format: "jwt_vc",
        types: [
          "VerifiableCredential",
          "VerifiableAttestation",
          "VerifiableAccreditation",
          "VerifiableAccreditationToAccredit",
        ],
        trust_framework: {
          name: "ebsi",
          type: "Accreditation",
          uri: "TIR link towards accreditation",
        },
        display: [
          { name: "Verifiable Accreditation to accredit", locale: "en-GB" },
        ],
      },
      {
        format: "jwt_vc",
        types: [
          "VerifiableCredential",
          "VerifiableAttestation",
          "VerifiableAuthorisationForTrustChain",
        ],
        trust_framework: {
          name: "ebsi",
          type: "Accreditation",
          uri: "TIR link towards accreditation",
        },
        display: [
          {
            name: "Verifiable Authorisation to issue verifiable tokens",
            locale: "en-GB",
          },
        ],
      },
      {
        format: "jwt_vc",
        types: [
          "VerifiableCredential",
          "VerifiableAttestation",
          "CTAAQualificationCredential",
        ],
        trust_framework: {
          name: "ebsi",
          type: "Accreditation",
          uri: "TIR link towards accreditation",
        },
        display: [
          {
            name: "Verifiable Attestation Conformance Qualification To Accredit & Authorise",
            locale: "en-GB",
          },
        ],
      },
      {
        format: "jwt_vc",
        types: [
          "VerifiableCredential",
          "VerifiableAttestation",
          "CTWalletQualificationCredential",
        ],
        trust_framework: {
          name: "ebsi",
          type: "Accreditation",
          uri: "TIR link towards accreditation",
        },
        display: [
          {
            name: "Verifiable Attestation Conformance Qualification Holder Wallet",
            locale: "en-GB",
          },
        ],
      },
      {
        format: "jwt_vc",
        types: [
          "VerifiableCredential",
          "VerifiableAttestation",
          "CTIssueQualificationCredential",
        ],
        trust_framework: {
          name: "ebsi",
          type: "Accreditation",
          uri: "TIR link towards accreditation",
        },
        display: [
          {
            name: "Verifiable Attestation Conformance Qualification Issue to Holder",
            locale: "en-GB",
          },
        ],
      },
    ],
  });
});

export default oidcRouter;