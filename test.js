import { Resolver } from "did-resolver";
import { getResolver } from "@cef-ebsi/key-did-resolver";

const decodePublicKey = (publicKey) => {
  const multicodecPubKey = base58btc.decode(publicKey);
  const [code, sizeOffset] = varint.decode(multicodecPubKey);
  const pubKeyBytes = multicodecPubKey.slice(sizeOffset);

  return {
    pubKeyBytes,
    code,
  };
};


const decode = (string, alphabet, bitsPerChar, name) => {
  // Build the character lookup table:
  const codes = {}
  for (let i = 0; i < alphabet.length; ++i) {
    codes[alphabet[i]] = i
  }

  // Count the padding bytes:
  let end = string.length
  while (string[end - 1] === '=') {
    --end
  }

  // Allocate the output:
  const out = new Uint8Array((end * bitsPerChar / 8) | 0)
  // Parse the data:
  let bits = 0 // Number of bits currently in the buffer
  let buffer = 0 // Bits waiting to be written out, MSB first
  let written = 0 // Next byte to write
  for (let i = 0; i < end; ++i) {
    // Read one character from the string:
    const value = codes[string[i]]
    if (value === undefined) {
      throw new SyntaxError(`Non-${name} character`)
    }

    // Append the bits to the buffer:
    buffer = (buffer << bitsPerChar) | value
    bits += bitsPerChar

    // Write out some bits if the buffer has a byte's worth:
    if (bits >= 8) {
      bits -= 8
      out[written++] = 0xff & (buffer >> bits)
    }
  }
  // Verify that we have received just enough bits:
  if (bits >= bitsPerChar || 0xff & (buffer << (8 - bits))) {
    throw new SyntaxError('Unexpected end of data')
  }
  return out
}



function reloveKeyDIDDoc(did) {
  const KEY_DID_METHOD_PREFIX = "did:key:";
  const base58btc = baseX({
    name: "base58btc",
    prefix: "z",
    alphabet: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
  });

  if (!did.startsWith(KEY_DID_METHOD_PREFIX)) {
    throw new InvalidDidError(
      `The DID must start with "${KEY_DID_METHOD_PREFIX}"`
    );
  }
  const methodSpecificIdentifier = did.substring(KEY_DID_METHOD_PREFIX.length);

  if (!methodSpecificIdentifier.startsWith(base58btc.prefix)) {
    throw new InvalidDidError(
      `The method-specific identifier must start with "${base58btc.prefix}" (multibase base58btc-encoded)`
    );
  }
}

// getResolver will return an object with a key/value pair of { "key": resolver } where resolver is a function used by the generic DID resolver.
const keyResolver = getResolver();
const didResolver = new Resolver(keyResolver);

// Example usage:
const multikey =
  "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbscXa1uGoenyfmUyYKdMPVCgBRJAwEFiH2CYjtyffkLL1sdSSZnPrJmoGNfmzKXF7m6KAq1WceuKRVSJEqquoBHzAeifmsMmFvaHiUZpHrFfhkhsxfgRVgqdRv9wia7d5Y8";

didResolver
  .resolve(multikey)
  .then((doc) =>
    console.log("%o", doc.didDocument.verificationMethod[0].publicKeyJwk)
  );
