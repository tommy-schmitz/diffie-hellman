(async() => {

  let iv;
  let ciphertext;

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
  async function encrypt(secretKey) {
    const ciphertextValue = document.querySelector(".ecdh .ciphertext-value");
    ciphertextValue.textContent = "";
    const decryptedValue = document.querySelector(".ecdh .decrypted-value");
    decryptedValue.textContent = "";

    iv = window.crypto.getRandomValues(new Uint8Array(12));
    let encoded = getMessageEncoding();

    ciphertext = await window.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv
      },
      secretKey,
      encoded
    );

    let buffer = new Uint8Array(ciphertext, 0, 5);
    ciphertextValue.classList.add("fade-in");
    ciphertextValue.addEventListener("animationend", () => {
      ciphertextValue.classList.remove("fade-in");
    });
    ciphertextValue.textContent = `${buffer}...[${ciphertext.byteLength} bytes total]`;
  }

  /*
  Decrypt the message using the secret key.
  If the ciphertext was decrypted successfully,
  update the "decryptedValue" box with the decrypted value.
  If there was an error decrypting,
  update the "decryptedValue" box with an error message.
  */
  async function decrypt(secretKey) {
    const decryptedValue = document.querySelector(".ecdh .decrypted-value");
    decryptedValue.textContent = "";
    decryptedValue.classList.remove("error");

    try {
      let decrypted = await window.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: iv
        },
        secretKey,
        ciphertext
      );

      let dec = new TextDecoder();
      decryptedValue.classList.add("fade-in");
      decryptedValue.addEventListener("animationend", () => {
        decryptedValue.classList.remove("fade-in");
      });
      decryptedValue.textContent = dec.decode(decrypted);
    } catch (e) {
      decryptedValue.classList.add("error");
      decryptedValue.textContent = "*** Decryption error ***";
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

  const my_key = await localforage.getItem('my keys');
  if(my_key === null) {
    generate_keys_div.style.display = '';

    name_input.addEventListener('input', async() => {
      if(name_input.value.length > 0)
        generate_button.disabled = false;
      else
        generate_button.disabled = true;
    });

    generate_button.addEventListener('click', async() => {
      console.log('3');
      const my_keys = await window.crypto.subtle.generateKey({name: "ECDH", namedCurve: "P-384"}, true, ["deriveKey"]);
      console.log('2');
/**
      const x = {
        publicKey: await crypto.subtle.exportKey('raw', my_keys.publicKey),
        privateKey: await crypto.subtle.exportKey('pkcs8', my_keys.privateKey),
      };
/**/
      const x = my_keys;
      console.log(x.publicKey);
      console.log(x.privateKey);
      console.log('1');
      await localforage.setItem('my keys', x);
//      await localforage.setItem('my private key', await crypto.subtle.exportKey('pkcs8', my_keys.privateKey));
      await update_model();
    });
  } else {
    my_public_key_div.style.display = '';
    console.log(my_key.publicKey);
    console.log(await crypto.subtle.exportKey('raw', my_key.publicKey));
    console.log(String.fromCharCode.apply(null, await crypto.subtle.exportKey('raw', my_key.publicKey)));
    const x1 = base56encode(await crypto.subtle.exportKey('raw', my_key.publicKey));
    const x2 = base56decode(x1);
    console.log(x2);
    const x3 = base56encode(x2);
    const x4 = base56decode(x3);
    console.log(x4);
    const x5 = base56encode(x4);
    my_public_key_pre.innerText = `${x1}
(blah)
${x3}
(blah)
${x5}`;
    choose_partner_div.style.display = '';
  }
};
await update_model();


})();