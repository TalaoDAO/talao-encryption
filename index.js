const crypto = require('crypto')
const NodeRSA = require('node-rsa')
const aesjs = require('aes-js')
const web3 = require('web3')

class TalaoEncryption {

  constructor() {
    this.rsa = null
    this.aes = null
  }

  generateRsa() {
    this.rsa = new NodeRSA({b: 2048})
    return this.rsa
  }

  loadRsa(pem) {
    this.rsa = new NodeRSA(pem)
    return this.rsa
  }

  getRsa() {
    return this.rsa
  }

  getPrivateRsa() {
    return this.rsa.exportKey('private')
  }

  getPublicRsa() {
    return this.rsa.exportKey('public')
  }

  getPublicRsaForEthereum() {
    return web3.utils.asciiToHex(this.getPublicRsa())
  }

  generateAes() {
    this.aes = crypto.randomFillSync(Buffer.alloc(16))
    return this.aes
  }

  loadAes(hex) {
    this.aes = Buffer.from(hex, 'hex')
    return this.aes
  }

  getAes() {
    return this.aes
  }

  getAesHex() {
    return this.aes.toString('hex')
  }

  rsaEncryptForEthereum(_clear) {
    const encrypted = this.rsa.encrypt(_clear)
    const encryptedHex = encrypted.toString('hex')
    return '0x' + encryptedHex
  }

  rsaEncryptAesForEthereum() {
    return this.rsaEncryptForEthereum(this.getAes())
  }

  rsaDecryptAesFromEthereum(ethereum) {
    const encrypted = ethereum.substr(2)
    const buffer = Buffer.from(encrypted, 'hex')
    return this.rsa.decrypt(buffer)
  }

  rsaDecryptAesFromEthereumAndLoad(ethereum) {
    const decrypted = this.rsaDecryptAesFromEthereum(ethereum)
    this.loadAes(decrypted)
  }

  aesEncrypt(text) {
    const bytes = aesjs.utils.utf8.toBytes(text)
    const ctr = new aesjs.ModeOfOperation.ctr(this.getAes(), new aesjs.Counter(5))
    const encryptedBytes = ctr.encrypt(bytes)
    const encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes)
    return encryptedHex
  }

  aesDecrypt(encryptedHex) {
    const encryptedBytes = aesjs.utils.hex.toBytes(encryptedHex)
    const ctr = new aesjs.ModeOfOperation.ctr(this.getAes(), new aesjs.Counter(5))
    const decryptedBytes = ctr.decrypt(encryptedBytes)
    const decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes)
    return decryptedText
  }

  aesEncryptForEthereum(text) {
    return '0x' + this.aesEncrypt(text)
  }

  aesDecryptFromEthereum(ethereum) {
    return this.aesDecrypt(ethereum.substr(2))
  }

}

module.exports = TalaoEncryption
