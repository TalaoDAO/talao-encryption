const assert = require('assert');
const web3 = require('web3');
const aesjs = require('aes-js');
const TalaoEncryption = require('../index');

let encryption;

describe('talao-encryption', function() {

  it('Should instantiate a encryption object', () => {
    encryption = new TalaoEncryption();
    assert(encryption);
  });

  it('Should generate an RSA key', function(done) {
    this.timeout(30000);
    const result = encryption.generateRsa();
    assert(result);
    done();
  });

  it('Should retrieve RSA\'s private PEM', () => {
    const result = encryption.getPrivateRsa();
    assert(result);
  });

  it('Should retrieve RSA\'s public PEM', () => {
    const result = encryption.getPublicRsa();
    assert(result);
  });

  it('Should build RSA key from local private PEM', () => {
    const encryption2 = new TalaoEncryption();
    encryption2.loadRsa(encryption.getPrivateRsa());
    const private2 = encryption2.getPrivateRsa();
    assert(encryption2.getRsa().isPrivate(true));
    assert.equal(private2, encryption.getPrivateRsa());
  });

  it('Someone should encrypt something on RSA\'s public and we should decrypt it with RSA\'s private', () => {
    // Someone encrypts.
    const encryption2 = new TalaoEncryption();
    encryption2.loadRsa(encryption.getPublicRsa());
    assert(encryption2.getRsa().isPublic(true));
    const encrypted = encryption2.getRsa().encrypt('Only for your eyes');
    // We decrypt.
    const decrypted = encryption.getRsa().decrypt(encrypted);
    // Test.
    assert.equal(decrypted, 'Only for your eyes');
  });

  it('Should get RSA public PEM for Ethereum', () => {
    const result = encryption.getPublicRsaForEthereum();
    assert(result);
  });

  it('Should generate an AES key', () => {
    const result = encryption.generateAes();
    assert(result);
  });

  it('Should encrypt AES key on public RSA key and return a bytes ready for Web3', () => {
    const result = encryption.rsaEncryptAesForEthereum();
    assert(result);
  });

  it('Should retrieve encrypted AES key from Ethereum and decrypt it', () => {
    // Instantiate new TalaoEncryption object.
    const encryption2 = new TalaoEncryption();
    // Build RSA key (emulate read from file).
    encryption2.loadRsa(encryption.getPrivateRsa());
    // Emulating call to Ethereum to get encrypted AES.
    const encryptedAesFromEthereum = encryption.rsaEncryptAesForEthereum();
    // Decrypt Ethereum data to get AES key.
    encryption2.rsaDecryptAesFromEthereumAndLoad(encryptedAesFromEthereum);
    assert.equal(encryption2.getAesHex(), encryption.getAesHex());
  });

  it('Should generate a secret, encrypt it and decrypt it', () => {
    encryption.generateAes();
    const secret = encryption.getAesHex();
    const encryptedSecret = encryption.rsaEncryptAesForEthereum();
    encryption.rsaDecryptAesFromEthereumAndLoad(encryptedSecret);
    const decryptedSecret = encryption.getAesHex();
    assert.equal(secret, decryptedSecret);
  });

  it('We should encrypt something on AES and someone else who has the AES should decrypt it', () => {
    // We encrypt.
    const encrypted = encryption.aesEncrypt('This is a shared content with those that have my AES key');
    // Someone else decrypts.
    const encryption2 = new TalaoEncryption();
    encryption2.loadAes(encryption.getAesHex());
    const decrypted = encryption.aesDecrypt(encrypted);
    // Compare.
    assert.equal(decrypted, 'This is a shared content with those that have my AES key');
  });

  it('We should encrypt something on AES and put it on the blockchain : someone else who has the AES should fetch it from the blockchain and decrypt it', () => {
    // We encrypt.
    const bcEncrypted = encryption.aesEncryptForEthereum('This is a shared content with those that have my AES key');
    // Someone else decrypts.
    const encryption2 = new TalaoEncryption();
    encryption2.loadAes(encryption.getAesHex());
    const decrypted = encryption.aesDecryptFromEthereum(bcEncrypted);
    // Compare.
    assert.equal(decrypted, 'This is a shared content with those that have my AES key');
  });

  // after(() => {
  //   console.log('\n');
  //   console.log('RSA private:\n' + encryption.getPrivateRsa() + '\n');
  //   console.log('RSA public:\n' + encryption.getPublicRsa() + '\n');
  //   console.log('AES:\n' + encryption.getAesHex() + '\n');
  //   console.log('Public RSA for Ethereum:\n' + encryption.getPublicRsaForEthereum() + '\n');
  //   console.log('Encrypted AES for Ethereum:\n' + encryption.rsaEncryptAesForEthereum() + '\n');
  // });

});
