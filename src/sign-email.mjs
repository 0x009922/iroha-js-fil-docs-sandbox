// @ts-check

import { crypto } from '@iroha2/crypto-target-node' // version: 1.0.0
import { freeScope } from '@iroha2/crypto-core' // version: 1.0.0

/**
 * @param {string} publicKeyHex - ed25519 pub key hex
 * @param {string} privateKeyHex - ed25519 private key hex
 * @param {string} email
 * @returns {string} - email signature hex
 */
function createEmailSignature(publicKeyHex, privateKeyHex, email) {
  return freeScope(() => {
    const keyPair = crypto.KeyPair.fromJSON({
      public_key: 'ed0120' + publicKeyHex,
      private_key: {
        digest_function: 'ed25519',
        payload: privateKeyHex,
      },
    })

    return keyPair.sign('array', new TextEncoder().encode(email)).payload('hex')
  })
}

// example signature
const signature = createEmailSignature(
  '7fbedb314a9b0c00caef967ac5cabb982ec45da828a0c58a9aafc854f32422ac',
  '413b285d1819a6166b0daa762bb6bef2d082cffb9a13ce041cb0fda5e2f06dc37fbedb314a9b0c00caef967ac5cabb982ec45da828a0c58a9aafc854f32422ac',
  'alice@wonderland.space'
)

console.log(signature)
// => 9729e8fbcd425bfe48809cc996c9e6d3cecddf0848a51d8758582b3c84bb2caca8e41a8290018aa7064f0b9ec61d2b1a155d5e4c772bc992d918528cf6cb6308
