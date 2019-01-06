const assert = require('assert');
const web3 = require('web3');
const aesjs = require('aes-js');
const TalaoEncryption = require('../index');

let talaoEncryption;

describe('talao-encryption', function() {

  it('Should instantiate a talaoEncryption object', () => {
    talaoEncryption = new TalaoEncryption();
    assert(talaoEncryption);
  });

  it('Should generate an RSA key', function(done) {
    this.timeout(30000);
    const result = talaoEncryption.generateRsa();
    assert(result);
    done();
  });

  it('Should retrieve RSA\'s private PEM', () => {
    const result = talaoEncryption.getPrivateRsa();
    assert(result);
  });

  it('Should retrieve RSA\'s public PEM', () => {
    const result = talaoEncryption.getPublicRsa();
    assert(result);
  });

  it('Should build RSA key from local private PEM', () => {
    const talaoEncryption2 = new TalaoEncryption();
    talaoEncryption2.loadRsa(talaoEncryption.getPrivateRsa());
    const private2 = talaoEncryption2.getPrivateRsa();
    assert(talaoEncryption2.getRsa().isPrivate(true));
    assert.equal(private2, talaoEncryption.getPrivateRsa());
  });

  it('Someone should encrypt something on RSA\'s public and we should decrypt it with RSA\'s private', () => {
    // Someone encrypts.
    const talaoEncryption2 = new TalaoEncryption();
    talaoEncryption2.loadRsa(talaoEncryption.getPublicRsa());
    assert(talaoEncryption2.getRsa().isPublic(true));
    const encrypted = talaoEncryption2.getRsa().encrypt('Only for your eyes');
    // We decrypt.
    const decrypted = talaoEncryption.getRsa().decrypt(encrypted);
    // Test.
    assert.equal(decrypted, 'Only for your eyes');
  });

  it('Should get RSA public PEM for Ethereum', () => {
    const result = talaoEncryption.getPublicRsaForEthereum();
    assert(result);
  });

  it('Should generate an AES key', () => {
    const result = talaoEncryption.generateAes();
    assert(result);
  });

  it('Should encrypt AES key on public RSA key and return a bytes ready for Web3', () => {
    const result = talaoEncryption.rsaEncryptAesForEthereum();
    assert(result);
  });

  it('Should retrieve encrypted AES key from Ethereum and decrypt it', () => {
    // Instantiate new TalaoEncryption object.
    const talaoEncryption2 = new TalaoEncryption();
    // Build RSA key (emulate read from file.)
    talaoEncryption2.loadRsa(talaoEncryption.getPrivateRsa());
    // Emulating call to Ethereum to get encrypted AES.
    const encryptedAesFromEthereum = talaoEncryption.rsaEncryptAesForEthereum();
    // Decrypt Ethereum data to get AES key.
    const aes = talaoEncryption2.rsaDecryptAesFromEthereum(encryptedAesFromEthereum);
    assert.equal(aes, talaoEncryption.getAesHex());
  });

  it('We should encrypt something on AES and someone else who has the AES should decrypt it', () => {
    // We encrypt.
    const encrypted = talaoEncryption.aesEncrypt('This is a shared content with those that have my AES key');
    // Someone else decrypts.
    const talaoEncryption2 = new TalaoEncryption();
    talaoEncryption2.loadAes(talaoEncryption.getAesHex());
    const decrypted = talaoEncryption.aesDecrypt(encrypted);
    // Compare.
    assert.equal(decrypted, 'This is a shared content with those that have my AES key');
  });

  it('We should encrypt something on AES and put it on the blockchain : someone else who has the AES should fetch it from the blockchain and decrypt it', () => {
    // We encrypt.
    const bcEncrypted = talaoEncryption.aesEncryptForEthereum('This is a shared content with those that have my AES key');
    // Someone else decrypts.
    const talaoEncryption2 = new TalaoEncryption();
    talaoEncryption2.loadAes(talaoEncryption.getAesHex());
    const decrypted = talaoEncryption.aesDecryptFromEthereum(bcEncrypted);
    // Compare.
    assert.equal(decrypted, 'This is a shared content with those that have my AES key');
  });

  after(() => {
    console.log('\n');
    console.log('RSA private:\n' + talaoEncryption.getPrivateRsa() + '\n');
    console.log('RSA public:\n' + talaoEncryption.getPublicRsa() + '\n');
    console.log('Encrypted AES for Ethereum:\n' + talaoEncryption.aesEncryptForEthereum() + '\n');
  });

});
