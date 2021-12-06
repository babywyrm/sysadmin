const jwt = require('jsonwebtoken')
const forge = require('node-forge')

const payload = {
  hello: 'world'
}

var keypair = forge.rsa.generateKeyPair({ bits: 2048 });
keypair = {
  public: forge.pki.publicKeyToPem(keypair.publicKey, 72),
  private: forge.pki.privateKeyToPem(keypair.privateKey, 72)
};

jwt.sign(payload, keypair.private, { algorithm: 'RS256' }, (error, token) => {
  if (error) {
    console.error(error)
  } else {
    console.log(token)
    console.log()
    console.log(keypair.public)
    console.log(keypair.private)
    console.log()

    jwt.verify(
      token,
      keypair.public,
      { algorithms: ['RS256'] },
      (error, payload) => {
        if (error) {
          console.error(error)
        } else {
          console.log(payload)
        }
      }
    )
  }
})
