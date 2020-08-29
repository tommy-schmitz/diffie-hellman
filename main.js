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

    return base56encode(iv_ciphertext.buffer);
  }

  /*
  Decrypt the message using the secret key.
  If the ciphertext was decrypted successfully,
  update the "decryptedValue" box with the decrypted value.
  If there was an error decrypting,
  update the "decryptedValue" box with an error message.
  */
  async function decrypt(secretKey, cipher) {
    try {
      const arraybuffer = base56decode(cipher);
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
    } catch (e) {
      return '(Unable to decrypt this!)';
    }
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

//  agreeSharedSecretKey();


await new Promise((resolve) => {
  window.onload = resolve;
});

await localforage.setDriver([
  localforage.INDEXEDDB,
  localforage.WEBSQL,
  localforage.LOCALSTORAGE
]);

const base56encode = function(buffer) {
  const BASE_62_ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const alpha = BASE_62_ALPHABET;
  const a = new Uint8Array(buffer);
  let result = '';
  let state = 0;
  let i;
  for(i=0; i<a.length*8; ++i) {
    const bit = (a[Math.floor(i/8)] >> (i%8)) % 2;
    state += bit << (i%23);
    if(i % 23 === 22) {
      result += alpha.charAt(                           state % 56);
      result += alpha.charAt(          Math.floor(state / 56) % 56);
      result += alpha.charAt(     Math.floor(state / 56 / 56) % 56);
      result += alpha.charAt(Math.floor(state / 56 / 56 / 56) % 56);
      state = 0;
    }
  }

  if(i % 23 <= 5) {
    result += alpha.charAt(state % 56);
  } else if(i % 23 <= 11) {
    result += alpha.charAt(                           state % 56);
    result += alpha.charAt(          Math.floor(state / 56) % 56);
  } else if(i % 23 <= 17) {
    result += alpha.charAt(                           state % 56);
    result += alpha.charAt(          Math.floor(state / 56) % 56);
    result += alpha.charAt(     Math.floor(state / 56 / 56) % 56);
  } else {
    result += alpha.charAt(                           state % 56);
    result += alpha.charAt(          Math.floor(state / 56) % 56);
    result += alpha.charAt(     Math.floor(state / 56 / 56) % 56);
    result += alpha.charAt(Math.floor(state / 56 / 56 / 56) % 56);
  }

  return result;
};
const base56decode = function(string) {
  const decode_one_char = function(c, i) {
    const n = c.charCodeAt(i);
    if(n <= 57)
      return n - 48;
    else if(n >= 97)
      return n - 97 + 10;
    else
      return n - 65 + 36;
  };
  const bits = [];
  for(let i=0; i<Math.floor(string.length/4); ++i) {
    const state = (
                         decode_one_char(string[4*i])
        +           56 * decode_one_char(string[4*i+1])
        +      56 * 56 * decode_one_char(string[4*i+2])
        + 56 * 56 * 56 * decode_one_char(string[4*i+3])
    );
    for(let j=0; j<23; ++j)
      bits.push((state >> j) % 2);
  }
  if(string.length % 4 === 1) {
    const state = (
                         decode_one_char(string[string.length - 1])
    );
    for(let j=0; j<6; ++j)
      bits.push((state >> j) % 2);
  }
  if(string.length % 4 === 2) {
    const state = (
                         decode_one_char(string[string.length - 2])
        +           56 * decode_one_char(string[string.length - 1])
    );
    for(let j=0; j<12; ++j)
      bits.push((state >> j) % 2);
  }
  if(string.length % 4 === 3) {
    const state = (
                         decode_one_char(string[string.length - 3])
        +           56 * decode_one_char(string[string.length - 2])
        +      56 * 56 * decode_one_char(string[string.length - 1])
    );
    for(let j=0; j<18; ++j)
      bits.push((state >> j) % 2);
  }

  console.log(bits);

  let state = 0;
  const result = [];
  for(let i=0; i<bits.length; ++i) {
    state += bits[i] << (i%8);
    if(i % 8 === 7) {
      result.push(state);
      state = 0;
    }
  }
  if(state !== 0)
    throw 'oh crap';

  return new Uint8Array(result).buffer;
};

const update_model = async function() {

  generate_keys_div.style.display = 'none';
  my_public_key_div.style.display = 'none';
  choose_partner_div.style.display = 'none';
  encrypt_or_decrypt_div.style.display = 'none';

  const my_keys = await localforage.getItem('my_keys');
  if(my_keys === null) {
    generate_keys_div.style.display = '';

    name_input.addEventListener('input', async() => {
      if(name_input.value.length > 0)
        generate_button.disabled = false;
      else
        generate_button.disabled = true;
    });

    generate_button.addEventListener('click', async() => {
      console.log('3');
      const keys = await window.crypto.subtle.generateKey({name: "ECDH", namedCurve: "P-384"}, true, ["deriveKey"]);
      console.log('2');
/**
      const x = {
        publicKey: await crypto.subtle.exportKey('raw', keys.publicKey),
        privateKey: await crypto.subtle.exportKey('pkcs8', keys.privateKey),
      };
/**/
      const x = keys;
      console.log(x.publicKey);
      console.log(x.privateKey);
      console.log('1');
      await localforage.setItem('my_keys', x);
//      await localforage.setItem('my private key', await crypto.subtle.exportKey('pkcs8', keys.privateKey));
      await update_model();
    });
  } else {
    my_public_key_div.style.display = '';
    my_public_key_pre.innerText = base56encode(await crypto.subtle.exportKey('raw', my_keys.publicKey));
    choose_partner_div.style.display = '';
    encrypt_or_decrypt_div.style.display = '';

    let symmetric_key = null;
    const update_symmetric_key = async function() {
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
    };
    let other_key = await localforage.getItem('other_key');
    partner_public_key_textarea.addEventListener('input', async() => {
      other_key = base56decode(partner_public_key_textarea.value);
      localforage.setItem('other_key', other_key);
      await update_symmetric_key();
    });
    if(other_key !== null) {
      partner_public_key_textarea.value = base56encode(other_key);
      await update_symmetric_key();
    }

    ciphertext_textarea.addEventListener('input', async() => {
      plaintext_pre.innerText = '';
    });
    plaintext_textarea.addEventListener('input', async() => {
      ciphertext_pre.innerText = '';
    });

    encrypt_button.addEventListener('click', async() => {
      ciphertext_pre.innerText = await encrypt(symmetric_key, plaintext_textarea.value);
    });
    decrypt_button.addEventListener('click', async() => {
      plaintext_pre.innerText = await decrypt(symmetric_key, ciphertext_textarea.value);
    });
  }
};
await update_model();


})();
