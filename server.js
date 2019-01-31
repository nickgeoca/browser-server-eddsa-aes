// To generate new ECDH keys, paste this code into browser, then run code below
//   https://raw.githubusercontent.com/CryptoEsel/js-x25519/master/lib/x25519.js.min.js
// > const ab2b64 = a => btoa(String.fromCharCode(...new Uint8Array(a)));
// > let private = window.crypto.getRandomValues(new Uint8Array(32));
// > let public  = ab2b64(X25519.getPublic(private));

// ************************************************
// Keys
const servSecretKey = b64ToAb('0eF4ZL7+nzssJ4BrpvIQoLKRHCxVFjt9n6tMu5xfYUw=');
const servPublicKey = b64ToAb('VG4lap1sZRUpAYb0sz3SAal56VdMbPNjvaQUh1zTtxA=');

exports.decrypt = req => {
        const data_b64_encr_formatted_str_json = req.body.data;
        const pubKey_b64 = req.body.pubKey;
        const iv_b64 = req.body.iv;
 
	// Validate request
	// replace with try-catch
	/*if(!data_b64) return res.status(400).send({message: "data cannot be empty"});
	if(!pubKey_b64) return res.status(400).send({message: "pubKey cannot be empty"});
	if(!iv_b64) return res.status(400).send({message: "iv cannot be empty"});
	*/
	// decrypt message here and pass to function below


        const clientPubKey_ab = b64ToAb(pubKey_b64);
        const sharedKey_b64 = ab2b64(getSharedSecretKey(clientPubKey_ab));
        const data_json = decryptToJson(data_b64_encr_formatted_str_json, sharedKey_b64, iv_b64);

	decrypted_req = req;
	decrypted_req.body = {...req.body, ...data_json}; // object spread
	delete decrypted_req.body.data_b64;
	delete decrypted_req.body.pubKey_b64;
	delete decrypted_req.body.iv_b64;
	return decrypted_req;
};

const crypto = require('crypto');
var ec25519 = require('curve25519-n');

// ************************************************
// Misc

const ab2b64 = ab => ab.toString('base64');
const b64ToAb = b64 => Buffer.from(b64, 'base64');

ec25519.makeSecretKey(servSecretKey);

// ************************************************
// Decryption

const decryptMsg = (encrMsgB64, keyB64, ivB64) => {
  let decrUtf8 = ''
  const key = Buffer.alloc(16, keyB64, 'base64');
  const iv  = Buffer.alloc(12, ivB64, 'base64');

  let decipher = crypto.createDecipheriv('aes-128-gcm', key, iv);
  decipher.on('readable', () => {
    const data = decipher.read();
    if (data) decrUtf8 += data.toString('utf8');
  });
  decipher.write(encrMsgB64, 'base64');
  // decipher.setAuthTag('') 
  // decipher.end();  // todo , memory leak?
  
  return decrUtf8;
}

const parseMsg = str => {
    const lenStr = str.split(' ')[0];
    const len = parseInt(lenStr);
    const lenLength = parseInt(lenStr.length) + 1;

    const s = str.slice(lenLength, len + lenLength);

    return JSON.parse(s);
  }

const decryptToJson = (encrMsgB64, keyB64, ivB64) => parseMsg(decryptMsg(encrMsgB64, keyB64, ivB64));

const getSharedSecretKey = clientPubKeyAb => ec25519.deriveSharedSecret(servSecretKey, clientPubKeyAb).slice(0,16);


