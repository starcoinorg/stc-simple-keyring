const EventEmitter = require('events').EventEmitter
const Wallet = require('@starcoin/stc-wallet')
const arrayify = require('@ethersproject/bytes').arrayify
const stcUtil = require('@starcoin/stc-util')
const { utils, encoding } = require('@starcoin/starcoin')
const sigUtil = require('eth-sig-util')

const type = 'Simple Key Pair'
class SimpleKeyring extends EventEmitter {

  /* PUBLIC METHODS */

  constructor(opts) {
    super()
    this.type = type
    this.wallets = []
    this.deserialize(opts)
  }

  serialize() {
    return Promise.resolve(this.wallets.map(w => ({ privateKey: w.getPrivateKey().toString('hex'), publicKey: w.getPublicKey().toString('hex') })))
  }

  deserialize(keyPairs = []) {
    return new Promise((resolve, reject) => {
      try {
        if (typeof keyPairs === 'object' && Object.keys(keyPairs).length === 0) {
          keyPairs = []
        }
        this.wallets = keyPairs.map(({ privateKey, publicKey }) => {
          const privateKeyStripped = stcUtil.stripHexPrefix(privateKey)
          const privateKeyBuffer = Buffer.from(privateKeyStripped, 'hex')
          const publicKeyStripped = stcUtil.stripHexPrefix(publicKey)
          const publicKeyBuffer = Buffer.from(publicKeyStripped, 'hex')
          const wallet = Wallet.fromPrivatePublic(privateKeyBuffer, publicKeyBuffer);
          return wallet
        })
      } catch (e) {
        reject(e)
      }
      resolve()
    })
  }

  addAccounts(n = 1) {
    var newWallets = []
    for (var i = 0; i < n; i++) {
      newWallets.push(Wallet.generate())
    }
    this.wallets = this.wallets.concat(newWallets)
    const hexWallets = newWallets.map(w => stcUtil.bufferToHex(w.getAddress()))
    return Promise.resolve(hexWallets)
  }

  getAccounts() {
    return Promise.resolve(this.wallets.map(w => stcUtil.bufferToHex(w.getAddress())))
  }

  // tx is rawUserTransaction.
  signTransaction(address, tx, opts = {}) {
    const privKey = this.getPrivateKeyFor(address, opts);
    const privKeyStr = stcUtil.addHexPrefix(privKey.toString('hex'))
    const hex = utils.tx.signRawUserTransaction(
      privKeyStr,
      tx,
    )
    return Promise.resolve(hex)
  }

  // For eth_sign, we need to sign arbitrary data:
  signMessage(address, data, opts = {}) {
    const message = stcUtil.stripHexPrefix(data)
    const privKey = this.getPrivateKeyFor(address, opts);
    var msgSig = stcUtil.ecsign(Buffer.from(message, 'hex'), privKey)
    var rawMsgSig = stcUtil.bufferToHex(sigUtil.concatSig(msgSig.v, msgSig.r, msgSig.s))
    return Promise.resolve(rawMsgSig)
  }

  // For eth_sign, we need to sign transactions:
  newGethSignMessage(withAccount, msgHex, opts = {}) {
    const privKey = this.getPrivateKeyFor(withAccount, opts);
    const msgBuffer = stcUtil.toBuffer(msgHex)
    const msgHash = stcUtil.hashPersonalMessage(msgBuffer)
    const msgSig = stcUtil.ecsign(msgHash, privKey)
    const rawMsgSig = stcUtil.bufferToHex(sigUtil.concatSig(msgSig.v, msgSig.r, msgSig.s))
    return Promise.resolve(rawMsgSig)
  }

  // For personal_sign, we need to prefix the message:
  signPersonalMessage(address, message, opts = {}) {
    const privKey = this.getPrivateKeyFor(address, opts);
    return utils.signedMessage.signMessage(message, privKey.toString('hex'))
      .then((payload) => {
        // const { publicKey, signature } = payload
        return payload
      })
  }

  // For stc_decrypt:
  decryptMessage(withAccount, encryptedData, opts) {
    const wallet = this._getWalletForAccount(withAccount, opts)
    const privKey = stcUtil.stripHexPrefix(wallet.getPrivateKey())
    const sig = sigUtil.decrypt(encryptedData, privKey)
    return Promise.resolve(sig)
  }

  // personal_signTypedData, signs data along with the schema
  signTypedData(withAccount, typedData, opts = { version: 'V1' }) {
    switch (opts.version) {
      case 'V1':
        return this.signTypedData_v1(withAccount, typedData, opts);
      case 'V3':
        return this.signTypedData_v3(withAccount, typedData, opts);
      case 'V4':
        return this.signTypedData_v4(withAccount, typedData, opts);
      default:
        return this.signTypedData_v1(withAccount, typedData, opts);
    }
  }

  // personal_signTypedData, signs data along with the schema
  signTypedData_v1(withAccount, typedData, opts = {}) {
    const privKey = this.getPrivateKeyFor(withAccount, opts);
    const sig = sigUtil.signTypedDataLegacy(privKey, { data: typedData })
    return Promise.resolve(sig)
  }

  // personal_signTypedData, signs data along with the schema
  signTypedData_v3(withAccount, typedData, opts = {}) {
    const privKey = this.getPrivateKeyFor(withAccount, opts);
    const sig = sigUtil.signTypedData(privKey, { data: typedData })
    return Promise.resolve(sig)
  }

  // personal_signTypedData, signs data along with the schema
  signTypedData_v4(withAccount, typedData, opts = {}) {
    const privKey = this.getPrivateKeyFor(withAccount, opts);
    const sig = sigUtil.signTypedData_v4(privKey, { data: typedData })
    return Promise.resolve(sig)
  }

  // get public key for nacl
  getEncryptionPublicKey(withAccount, opts = {}) {
    const privKey = this.getPrivateKeyFor(withAccount, opts);
    const publicKey = sigUtil.getEncryptionPublicKey(privKey)
    return Promise.resolve(publicKey)
  }

  // get public key
  getPublicKeyFor(withAccount, opts = {}) {
    const privKey = this.getPrivateKeyFor(withAccount, opts);
    const privKeyStr = stcUtil.addHexPrefix(privKey.toString('hex'))
    const publicKey = encoding.privateKeyToPublicKey(privKeyStr)
    return Promise.resolve(publicKey)
  }

  getPrivateKeyFor(address, opts = {}) {
    if (!address) {
      throw new Error('Must specify address.');
    }
    const wallet = this._getWalletForAccount(address, opts)
    const privKey = stcUtil.toBuffer(wallet.getPrivateKey())
    return privKey;
  }

  // returns an address specific to an app
  getAppKeyAddress(address, origin) {
    return new Promise((resolve, reject) => {
      try {
        const wallet = this._getWalletForAccount(address, {
          withAppKeyOrigin: origin,
        })
        const appKeyAddress = sigUtil.normalize(wallet.getAddress().toString('hex'))
        return resolve(appKeyAddress)
      } catch (e) {
        return reject(e)
      }
    })
  }

  // exportAccount should return a hex-encoded private key:
  exportAccount(address, opts = {}) {
    const wallet = this._getWalletForAccount(address, opts)
    return Promise.resolve(wallet.getPrivateKey().toString('hex'))
  }

  removeAccount(address) {
    if (!this.wallets.map(w => stcUtil.bufferToHex(w.getAddress()).toLowerCase()).includes(address.toLowerCase())) {
      throw new Error(`Address ${ address } not found in this keyring`)
    }
    this.wallets = this.wallets.filter(w => stcUtil.bufferToHex(w.getAddress()).toLowerCase() !== address.toLowerCase())
  }

  getReceiptIdentifier(address, opts = {}) {
    const wallet = this._getWalletForAccount(address, opts)
    return Promise.resolve(wallet.getReceiptIdentifier())
  }

  /* PRIVATE METHODS */

  _getWalletForAccount(account, opts = {}) {
    const address = sigUtil.normalize(account)
    let wallet = this.wallets.find(w => stcUtil.bufferToHex(w.getAddress()) === address)
    if (!wallet) throw new Error('Simple Keyring - Unable to find matching address.')

    if (opts.withAppKeyOrigin) {
      const privKey = wallet.getPrivateKey()
      const appKeyOriginBuffer = Buffer.from(opts.withAppKeyOrigin, 'utf8')
      const appKeyBuffer = Buffer.concat([privKey, appKeyOriginBuffer])
      const appKeyPrivKey = stcUtil.keccak(appKeyBuffer, 256)
      wallet = Wallet.fromPrivateKey(appKeyPrivKey)
    }

    return wallet
  }

}

SimpleKeyring.type = type
module.exports = SimpleKeyring
