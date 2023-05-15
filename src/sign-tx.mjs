// @ts-check

import { crypto } from '@iroha2/crypto-target-node' // version: 1.0.0
import * as datamodel from '@iroha2/data-model' // version: 4.1.0
import { signTransaction, setCrypto, Signer } from '@iroha2/client' // version: 4.1.0
import { freeScope } from '@iroha2/crypto-core' // version: 1.0.0

setCrypto(crypto)

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function bytesToHex(bytes) {
  return Array.from(bytes, (v) => v.toString(16).padStart(2, '0')).join('')
}

/**
 *
 * @param {string} hex
 * @returns {Uint8Array}
 */
function hexToBytes(hex) {
  /** @type {number[]} */
  const bytes = []
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.slice(i, i + 2), 16))
  }
  return Uint8Array.from(bytes)
}

/**
 * @param {datamodel.SignedTransaction} tx
 * @param {import('@iroha2/crypto-core').KeyPair} keyPair
 * @return {datamodel.SignedTransaction}
 */
function appendSignatureWithKeyPair(tx, keyPair) {
  const signer = new Signer(tx.payload.account_id, keyPair)
  const signature = signTransaction(tx.payload, signer)
  return datamodel.SignedTransaction({
    payload: tx.payload,
    signatures: [...tx.signatures, signature],
  })
}

/**
 * @param {string} publicKeyHex - ed25519 pub key hex
 * @param {string} privateKeyHex - ed25519 private key hex
 * @param {string} transaction - hex of the transaction
 * @returns {string} - hex of the transaction with the appended signature
 */
function appendSignature(publicKeyHex, privateKeyHex, transaction) {
  return freeScope(() => {
    const keyPair = crypto.KeyPair.fromJSON({
      public_key: 'ed0120' + publicKeyHex,
      private_key: {
        digest_function: 'ed25519',
        payload: privateKeyHex,
      },
    })

    const txDecoded = datamodel.VersionedSignedTransaction.fromBuffer(
      hexToBytes(transaction)
    )

    const txNew = datamodel.VersionedSignedTransaction(
      'V1',
      appendSignatureWithKeyPair(txDecoded.as('V1'), keyPair)
    )

    return bytesToHex(datamodel.VersionedSignedTransaction.toBuffer(txNew))

    return bytesToHex(datamodel.VersionedSignedTransaction.toBuffer(txNew))
  })
}

// example signature
const tx = appendSignature(
  '7fbedb314a9b0c00caef967ac5cabb982ec45da828a0c58a9aafc854f32422ac',
  '413b285d1819a6166b0daa762bb6bef2d082cffb9a13ce041cb0fda5e2f06dc37fbedb314a9b0c00caef967ac5cabb982ec45da828a0c58a9aafc854f32422ac',
  '0114616c69636528776f6e6465726c616e640004000d09001468656c6c6f00002cde318c87010000a0860100000000000000041c65643235353139807233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c00101bef276fc36ba638abd422e76fd0e6df319df1c3d336ab60d7276333b4010bb7d962d04b273d9caf91cb8509581c0b55e1cdee371c52863a8b4b62c67fbfc870f'
)

console.log(tx)
// => 0114616c69636528776f6e6465726c616e640004000d09001468656c6c6f00002cde318c87010000a0860100000000000000081c65643235353139807233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c00101bef276fc36ba638abd422e76fd0e6df319df1c3d336ab60d7276333b4010bb7d962d04b273d9caf91cb8509581c0b55e1cdee371c52863a8b4b62c67fbfc870f1c65643235353139807fbedb314a9b0c00caef967ac5cabb982ec45da828a0c58a9aafc854f32422ac01014a3cffcfb6276cc6de039c3ab287e7614e6dffc5e152200efa817d59c04334839c9624781bb1bda7b1d5ead0f0ea1c31238cccf9a948becf71d09728c4914d0d
