const { jwtDecrypt } = require('jose/jwt/compact/decrypt');
const { createRemoteJWKSet } = require('jose/jwks/remote');

async function decryptJWE(jweToken) {
    try {
        // Define the URL from which to fetch the JWK set (public key)
        const jwksUri = 'https://example.com/.well-known/jwks.json';

        // Create a RemoteJWKSet instance to fetch the JWK set from the specified URL
        const remoteJWKS = createRemoteJWKSet(new URL(jwksUri));

        // Decrypt the JWE using the remote JWK set
        const decryptedPayload = await jwtDecrypt(jweToken, remoteJWKS);

        // Return the decrypted payload
        return decryptedPayload.plaintext.toString();
    } catch (error) {
        console.error('Error decrypting JWE:', error.message);
        throw error;
    }
}

// Example JWE token
const jweToken = 'eyJhbGciOiJQQjEtUFM3OTQiLCJlbmMiOiJBMTI4Q0JDLUhTMzg0Iiwia2lkIjoiUkZpZUpDQWl3azB2QmN1YlpQR1dsTm1CdnliRVZJUDl0SG9wQndKY0lUUSJ9.MFe_yErGma6vzaf2w6zA1C9r-3TqUY_zxZzfEv4EB99ikmmz4yYn2A.eaBnmQJQ8JxyEbW7qZ8qbg.MWcX6-8xkTgT_iXVG3xyQw.u1q_K2rjVJnGC8ZcCwRpHytJL51_D6lpIW8YecwLxcoByLHJ2RG2kAB1Xm8Jd_Bd-0VWE8FM03zyhQIBmYPSuzjjtW2ZIYdswqDpoe3__xI-qAoXkOowm4Yrmw1R6Q.2wByOlyM_6K4WPlJg7nYnA';

// Decrypt the JWE and log the decrypted payload
decryptJWE(jweToken)
    .then((decryptedPayload) => {
        console.log('Decrypted Payload:', decryptedPayload);
    })
    .catch((error) => {
        console.error('Error:', error.message);
    });
