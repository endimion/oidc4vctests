import { Resolver } from "did-resolver";
import { getResolver } from "@cef-ebsi/key-did-resolver";
 
// getResolver will return an object with a key/value pair of { "key": resolver } where resolver is a function used by the generic DID resolver.
const keyResolver = getResolver();
const didResolver = new Resolver(keyResolver);


// Example usage:
const multikey =
  "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbscXa1uGoenyfmUyYKdMPVCgBRJAwEFiH2CYjtyffkLL1sdSSZnPrJmoGNfmzKXF7m6KAq1WceuKRVSJEqquoBHzAeifmsMmFvaHiUZpHrFfhkhsxfgRVgqdRv9wia7d5Y8";

  didResolver
  .resolve(
   multikey
  )
  .then((doc) => console.log('%o', doc.didDocument.verificationMethod[0].publicKeyJwk));