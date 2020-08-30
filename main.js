// TODO:
//  * Either remove the requirement of entering your name, or ...
//  * Add support for saving multiple public keys, and auto-attach name to public keys.
//  * readonly textarea

(async() => {

  /*
  Fetch the contents of the "message" textbox, and encode it
  in a form we can use for the encrypt operation.
  */
  function getMessageEncoding() {
    let message = document.querySelector("#ecdh-message").value;
    let enc = new TextEncoder();
    return enc.encode(message);
  }

  /*
  Encrypt the message using the secret key.
  Update the "ciphertextValue" box with a representation of part of
  the ciphertext.
  */
  async function encrypt(secretKey, msg) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    let encoded = new TextEncoder().encode(msg);

    const ciphertext = await window.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv
      },
      secretKey,
      encoded
    );

    const iv_ciphertext = new Uint8Array(12 + ciphertext.byteLength);
    iv_ciphertext.set(iv, 0);
    iv_ciphertext.set(new Uint8Array(ciphertext), 12);

    return base58encode(iv_ciphertext.buffer);
  }

  /*
  Decrypt the message using the secret key.
  If the ciphertext was decrypted successfully,
  update the "decryptedValue" box with the decrypted value.
  If there was an error decrypting,
  update the "decryptedValue" box with an error message.
  */
  async function decrypt(secretKey, cipher) {
    const arraybuffer = base58decode(cipher);
    let decrypted = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: arraybuffer.slice(0, 12)
      },
      secretKey,
      arraybuffer.slice(12)
    );

    let dec = new TextDecoder();
    return dec.decode(decrypted);
  }

  /*
  Derive an AES key, given:
  - our ECDH private key
  - their ECDH public key
  */
  function deriveSecretKey(privateKey, publicKey) {
    return window.crypto.subtle.deriveKey(
      {
        name: "ECDH",
        public: publicKey
      },
      privateKey,
      {
        name: "AES-GCM",
        length: 256
      },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function agreeSharedSecretKey() {
    // Generate 2 ECDH key pairs: one for Alice and one for Bob
    // In more normal usage, they would generate their key pairs
    // separately and exchange public keys securely
    let alicesKeyPair = await window.crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: "P-384"
      },
      false,
      ["deriveKey"]
    );

    let bobsKeyPair = await window.crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: "P-384"
      },
      false,
      ["deriveKey"]
    );

    // Alice then generates a secret key using her private key and Bob's public key.
    let alicesSecretKey = await deriveSecretKey(alicesKeyPair.privateKey, bobsKeyPair.publicKey);

    // Bob generates the same secret key using his private key and Alice's public key.
    let bobsSecretKey = await deriveSecretKey(bobsKeyPair.privateKey, alicesKeyPair.publicKey);

    // Alice can then use her copy of the secret key to encrypt a message to Bob.
    let encryptButton = document.querySelector(".ecdh .encrypt-button");
    encryptButton.addEventListener("click", () => {
      encrypt(alicesSecretKey);
    });

    // Bob can use his copy to decrypt the message.
    let decryptButton = document.querySelector(".ecdh .decrypt-button");
    decryptButton.addEventListener("click", () => {
      decrypt(bobsSecretKey);
    });
  }


let my_keys = null;
let symmetric_key = null;

await new Promise((resolve) => {
  window.onload = resolve;
});

await localforage.setDriver([
  localforage.INDEXEDDB,
  localforage.WEBSQL,
  localforage.LOCALSTORAGE
]);

const to_b58 = function(B,A){var d=[],s="",i,j,c,n;for(i in B){j=0,c=B[i];s+=c||s.length^i?"":1;while(j in d||c){n=d[j];n=n?n*256+c:c;c=n/58|0;d[j]=n%58;j++}}while(j--)s+=A[d[j]];return s};
const from_b58 = function(S,A){var d=[],b=[],i,j,c,n;for(i in S){j=0,c=A.indexOf(S[i]);if(c<0)return undefined;c||b.length^i?i:b.push(0);while(j in d||c){n=d[j];n=n?n*58+c:c;c=n>>8;d[j]=n%256;j++}}while(j--)b.push(d[j]);return new Uint8Array(b)};

window.base58encode = function(buffer) {
  return to_b58(new Uint8Array(buffer), '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz');
};
window.base58decode = function(string) {
  return from_b58(string, '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz').buffer;
};

name_input.addEventListener('input', async() => {
  if(name_input.value.length > 0)
    generate_button.disabled = false;
  else
    generate_button.disabled = true;
});

generate_button.addEventListener('click', async() => {
  console.log('3');
  const keys = await window.crypto.subtle.generateKey({name: "ECDH", namedCurve: "P-384"}, false, ["deriveKey"]);
  console.log('2');
  const x = keys;
  console.log(x.publicKey);
  console.log(x.privateKey);
  console.log('1');
  await localforage.setItem('my_keys', x);
  await update_model();
});

let ppktv_dirty = false;
partner_public_key_textarea.addEventListener('input', async() => {
  ppktv_dirty = true;
});
setInterval(async() => {
  if(ppktv_dirty) {
    ppktv_dirty = false;
    await localforage.setItem('partner_public_key_textarea.value', partner_public_key_textarea.value);
    await update_model();
  }
}, 250);

const update_styles = function() {
  {
    const style = ciphertext_readonly.style;
    if(ciphertext_readonly.value.length > 0)
      style.visibility = '';
    else
      style.visibility = 'hidden';
  }

  {
    const style = plaintext_readonly.style;
    if(plaintext_readonly.value.length > 0)
      style.visibility = '';
    else
      style.visibility = 'hidden';
  }
};

ciphertext_textarea.addEventListener('input', async() => {
  plaintext_readonly.value = '';
  update_styles();
});
plaintext_textarea.addEventListener('input', async() => {
  ciphertext_readonly.value = '';
  update_styles();
});

encrypt_button.addEventListener('click', async() => {
  ciphertext_readonly.value = await encrypt(symmetric_key, plaintext_textarea.value);
  update_styles();
});
decrypt_button.addEventListener('click', async() => {
  try {
    plaintext_readonly.style.color = 'black';
    plaintext_readonly.value = await decrypt(symmetric_key, ciphertext_textarea.value);
  } catch(e) {
    plaintext_readonly.style.color = 'red';
    plaintext_readonly.value = '(Unable to decrypt this!)';
  }
  update_styles();
});

const update_model = async function() {
  my_keys = await localforage.getItem('my_keys');
  const my_public_key_buffer = my_keys!==null ? await crypto.subtle.exportKey('raw', my_keys.publicKey) : null;
  const ppktv = await localforage.getItem('partner_public_key_textarea.value');
  let other_key = null;
  try {
    other_key = base58decode(ppktv);
  } catch {}
  symmetric_key = null;
  if(other_key !== null) {
    try {
      symmetric_key = await deriveSecretKey(
        my_keys.privateKey,
        await crypto.subtle.importKey(
          'raw',
          other_key,
          {
            name: 'ECDH',
            namedCurve: 'P-384',
          },
          true,
          []
        )
      );
    } catch {}
  }

  generate_keys_div.style.display = 'none';
  my_public_key_div.style.display = 'none';
  choose_partner_div.style.display = 'none';
  encrypt_or_decrypt_div.style.display = 'none';

  if(my_keys === null) {
    generate_keys_div.style.display = '';
    return;
  }

  my_public_key_div.style.display = '';
  my_public_key_readonly.value = base58encode(my_public_key_buffer);

  choose_partner_div.style.display = '';

  if(symmetric_key !== null) {
    encrypt_or_decrypt_div.style.display = '';
    partner_public_key_textarea.value = base58encode(other_key);
  }
};
await update_model();
update_styles();


})();
