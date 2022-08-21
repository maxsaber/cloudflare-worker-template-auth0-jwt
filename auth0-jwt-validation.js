/**
 * Following code is based on code found at https://blog.cloudflare.com/dronedeploy-and-cloudflare-workers/
 * but has been modified to make it work for Auth0. Details here: https://liftcodeplay.com/2018/10/01/validating-auth0-jwts-on-the-edge-with-a-cloudflare-worker/
 */

/**
 * Parse the JWT and validate it.
 *
 * We are just checking that the signature is valid, but you can do more that. 
 * For example, check that the payload has the expected entries or if the signature is expired..
 */ 
async function isValidJwt(request) {
  const encodedToken = getJwt(request);
  if (encodedToken === null) {
    return false
  }
  const token = decodeJwt(encodedToken);

  // Is the token expired?
  let expiryDate = new Date(token.payload.exp * 1000)
  let currentDate = new Date(Date.now())
  if (expiryDate <= currentDate) {
    console.log('expired token')
    return false
  }

  return isValidJwtSignature(token)
}

/**
 * For this example, the JWT is passed in as part of the Authorization header,
 * after the Bearer scheme.
 * Parse the JWT out of the header and return it.
 */
function getJwt(request) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || authHeader.substring(0, 6) !== 'Bearer') {
    return null
  }
  return authHeader.substring(6).trim()
}

/**
 * Parse and decode a JWT.
 * A JWT is three, base64 encoded, strings concatenated with ‘.’:
 *   a header, a payload, and the signature.
 * The signature is “URL safe”, in that ‘/+’ characters have been replaced by ‘_-’
 * 
 * Steps:
 * 1. Split the token at the ‘.’ character
 * 2. Base64 decode the individual parts
 * 3. Retain the raw Bas64 encoded strings to verify the signature
 */
function decodeJwt(token) {
  const parts = token.split('.');
  const header = JSON.parse(atob(parts[0]));
  const payload = JSON.parse(atob(parts[1]));
  const signature = atob(parts[2].replace(/_/g, '/').replace(/-/g, '+'));
  console.log(header)
  return {
    header: header,
    payload: payload,
    signature: signature,
    raw: { header: parts[0], payload: parts[1], signature: parts[2] }
  }
}

/**
 * Validate the JWT.
 *
 * Steps:
 * Reconstruct the signed message from the Base64 encoded strings.
 * Load the RSA public key into the crypto library.
 * Verify the signature with the message and the key.
 */
async function isValidJwtSignature(token) {
  const encoder = new TextEncoder();
  const data = encoder.encode([token.raw.header, token.raw.payload].join('.'));
  const signature = new Uint8Array(Array.from(token.signature).map(c => c.charCodeAt(0)));

  // You need to JWK data with whatever is your public RSA key. If you're using Auth0 you
  // can download it from https://[your_domain].auth0.com/.well-known/jwks.json

  // The following is setup with the data from an application www.wolftracker.nz 
  // The JWK is available here: https://wolftracker.au.auth0.com/.well-known/jwks.json
  const jwk = {
    alg: "RS256",
    kty: "RSA",
    key_ops: ['verify'],
    use: "sig",
    x5c: ["MIIDBTCCAe2gAwIBAgIJHX3pnD45alEtMA0GCSqGSIb3DQEBCwUAMCAxHjAcBgNVBAMTFW1heHNhYmVyLnVzLmF1dGgwLmNvbTAeFw0yMjA4MjAxODM5MTJaFw0zNjA0MjgxODM5MTJaMCAxHjAcBgNVBAMTFW1heHNhYmVyLnVzLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAO/+UBJbwFyahMSnIamLsA+was62nCEighGeQ6ogws95fJb0SQBdUcUDkmWnQwvNjBwR6IdD/fLl7FyfpFkaqq/BSMvPaPI2lc80mYCDishfAaVJUhg+KtGZnfRdVbXPG6HtWyxSVVKx2zgzsMPUFcLsPWu2tlll53qr+/edKgZt90NfhtHy9q1K1NntLIYiYRw9MpVdQ1DDYqawBVdRQF5ZZb4yq5KQSjHQBqqzV9F4R15pJ161znYi7x9TYCILkHWUAfO5CmDB9MHMC+HrFx+GzjQMpmmLDM/46Cm2nriHbl/K07OHY2MoixrGHZKXzWRHorHQ1csj6v5HZfavVKMCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUQBT3N8F6FJmnKFETfe0Aa/otxnUwDgYDVR0PAQH/BAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQBPFMRWhIN6/yfrbaEQg/rRFqUlHq/5dcx4jOg661JWuY/9BDJCzMzbAG98OCvz79bR50Nsni+rBeYQkoh2wzEL279vFskXBpDo5Ds8zH0RBmFQAJ6xzMi/wvZsIglwoTSEFOQpDV3H64A4A2FEXaggYOVeLoH3AL6VOs5l1y5PSRZuaF7Q3VQ0G109j0rwYbfKxWSAa/ftLXtbDPppOoopyojo3xcDzikosKrCJQXhtdHEciaule47KhpQxN68KlittpL+p5s7kN8a51KRX3kIfsxHECLCdv3Nz6IUuLN2cZmaF5V9RlLO4gp9fWMfwkS8QZNP3DqOTJBxqP+GoQ8j"],
    n: "7_5QElvAXJqExKchqYuwD7BqzracISKCEZ5DqiDCz3l8lvRJAF1RxQOSZadDC82MHBHoh0P98uXsXJ-kWRqqr8FIy89o8jaVzzSZgIOKyF8BpUlSGD4q0Zmd9F1Vtc8boe1bLFJVUrHbODOww9QVwuw9a7a2WWXneqv7950qBm33Q1-G0fL2rUrU2e0shiJhHD0ylV1DUMNiprAFV1FAXlllvjKrkpBKMdAGqrNX0XhHXmknXrXOdiLvH1NgIguQdZQB87kKYMH0wcwL4esXH4bONAymaYsMz_joKbaeuIduX8rTs4djYyiLGsYdkpfNZEeisdDVyyPq_kdl9q9Uow",
    e: "AQAB",
    kid: "ZBRBDUoKA2ngN2CpsFIJ7",
    x5t: "_vx5-xRLSjoTgGpUU-LwFcwaOic"
    }
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  return crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, data)
}

export default { isValidJwt }