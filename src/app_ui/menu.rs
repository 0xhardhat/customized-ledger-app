/*****************************************************************************
 *   Ledger App Boilerplate Rust.
 *   (c) 2023 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

 use include_gif::include_gif;
 use ledger_device_sdk::io::Comm;
 
 use crate::settings::Settings;
 use ledger_device_sdk::nbgl::{NbglGlyph, NbglHomeAndSettings};
 
 // part for encryption
 
 use alloc::vec::Vec;
 // use alloc::string::ToString;
 use alloc::string::String;
 
 use aes_gcm::aead::{Aead, Payload, Nonce};
 use aes_gcm::{Aes256Gcm, Key, KeyInit}; 
 
 use hmac::{Hmac, Mac as MacTrait};  
 use sha2::{Sha512, Sha256, Digest};
 
 use generic_array::{GenericArray, typenum::U32};
 use generic_array::typenum::U12; 
 use hex::FromHex;  
 

 use ledger_device_sdk::ecc::Secp256k1;

 use serde_json::json;
 use crate::alloc::string::ToString;
 
 type HmacSha256 = Hmac<Sha256>; 
 
 fn hex_str_to_bytes(hex: &str) -> Vec<u8> {  
     Vec::from_hex(hex).expect("Invalid hex string")  
 }  
 
 pub fn encrypt_message(
     message: &[u8],
     recipient_public_key_bytes: &[u8],
 ) -> serde_json::Value {
     // Generate ephemeral key pair
     // let ephemeral_private_bytes = [/* generate 32 random bytes */];
     let mut ephemeral_private_bytes = [0u8; 32];
     let mut counter: u8 = 0;
     while counter < 32 {
     ephemeral_private_bytes[counter as usize] = counter.wrapping_mul(7);
     counter = counter.wrapping_add(1);
     }
 
     let ephemeral_sk = Secp256k1::from(&ephemeral_private_bytes);
     let ephemeral_pk = ephemeral_sk.public_key().unwrap();
     
     // Generate shared secret using recipient's public key
     let shared_secret = ephemeral_sk.ecdh(recipient_public_key_bytes).unwrap();
     let shared_secret_bytes = shared_secret.as_ref();
 
     let hash = Sha512::digest(shared_secret_bytes);
     let enc_key = &hash[..32];
     let mac_key = &hash[32..64];
 
     let mut key_array: GenericArray<u8, U32> = GenericArray::default();
     key_array.copy_from_slice(enc_key);
     
     let key: Key<Aes256Gcm> = key_array.into();
     let cipher = Aes256Gcm::new(&key);
 
     let mut iv = [0u8; 12];
     let mut counter: u8 = 0;
     while counter < 12 {
         iv[counter as usize] = counter.wrapping_mul(13);
         counter = counter.wrapping_add(1);
     }
 
     let nonce = Nonce::<Aes256Gcm>::from(iv);
 
     let ephem_pub_key_bytes = ephemeral_pk.pubkey.as_ref();
 
     let payload = Payload {
         msg: message,
         aad: ephem_pub_key_bytes,
     };
 
     let ciphertext = cipher.encrypt(&nonce, payload)
         .expect("Encryption failed!");
 
     let mut mac_calculator = <HmacSha256 as KeyInit>::new_from_slice(mac_key)
         .expect("HMAC initialization failed");
     mac_calculator.update(&iv);
     mac_calculator.update(ephem_pub_key_bytes);
     mac_calculator.update(&ciphertext);
     let mac = mac_calculator.finalize();
 
     json!({
         "iv": hex::encode(iv),
         "ephemPublicKey": hex::encode(ephem_pub_key_bytes),
         "ciphertext": hex::encode(ciphertext),
         "mac": hex::encode(mac.into_bytes())
     })
 }
 
 pub fn ui_menu_main<N, TY, P>(_: &mut Comm) -> NbglHomeAndSettings {
     // Load glyph from 64x64 4bpp gif file with include_gif macro. Creates an NBGL compatible glyph.
     #[cfg(any(target_os = "stax", target_os = "flex"))]
     const FERRIS: NbglGlyph = NbglGlyph::from_include(include_gif!("crab_64x64.gif", NBGL));
     #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
     const FERRIS: NbglGlyph = NbglGlyph::from_include(include_gif!("crab_16x16.gif", NBGL));
 
     let settings_strings = [["Display Memo", "Allow display of transaction memo."]];
     let mut settings: Settings = Default::default();
 
     // part for encryption.
     let message = "Hi, Anton!".as_bytes();
     let pubkey_bytes = hex::decode("04ef5b152e3f15eb0c50c9916161c2309e54bd87b9adce722d69716bcdef85f547678e15ab40a78919c7284e67a17ee9a96e8b9886b60f767d93023bac8dbc16e4").unwrap();
     let encrypted = encrypt_message(
         message,
         &pubkey_bytes
     );
     let encrypted_json = encrypted.to_string();
 
     // // part for decryption
     // let encrypted_data = r#"{  
     //     "iv": "fc623e3e5606275ea7944274",  
     //     "ephemPublicKey": "0462587c0bd9390d13cfacc6fffcdcad8ce90691c4f71224fbbf6f28711930c85f62d68300dcfb0d714d47bcdcf69f7d31e4be5fc16df4376abb4e0ff5b1a6d940",  
     //     "ciphertext": "9a3981cd192b58ee75ba993e762f4e669eaf4007",  
     //     "mac": "c51d3a0a058deb4cd70ca8967a2493ac4cf1004a806b6ef2eeca83a7ec7b957d"  
     // }"#;  encrypted_data generated by rust's native escp256k1 crate, this isn't decrypted by ledger's escp256k1
 
     // let data: serde_json::Value = serde_json::from_str(encrypted_data).unwrap();  
     let data: serde_json::Value = serde_json::from_str(&encrypted_json).unwrap();  
 
 
     let iv_hex = data["iv"].as_str().unwrap();  
     let ephem_pub_key_hex = data["ephemPublicKey"].as_str().unwrap();  
     let ciphertext_hex = data["ciphertext"].as_str().unwrap();  
 
     let iv = hex_str_to_bytes(iv_hex);  
     let ephem_pub_key = hex_str_to_bytes(ephem_pub_key_hex);  
     let ciphertext = hex_str_to_bytes(ciphertext_hex);  
 
     let private_key_hex = "ea2861b1058084974c509a4d2e21e73896059c1c69f7a5c2650661cac3493725";
     let private_key_bytes = hex_str_to_bytes(private_key_hex);  
 
     let sk = Secp256k1::from(&private_key_bytes);

     let mut pub_key = sk.public_key().unwrap();
     pub_key.pubkey.copy_from_slice(&ephem_pub_key);
     
     let shared_secret = sk.ecdh(&ephem_pub_key).unwrap();
     let shared_secret_bytes = shared_secret.as_ref(); 
     let shared_secret_hex = hex::encode(shared_secret_bytes);
 
     let hash = Sha512::digest(shared_secret_bytes);
     // let hash_hex = hex::encode(hash);
   
     let enc_key = &hash[..32];
     // let _mac_key = &hash[32..64];
     
     let mut key_array: GenericArray<u8, U32> = GenericArray::default();
     key_array.copy_from_slice(enc_key); 
     
     let key: Key<Aes256Gcm> = key_array.into();
     let cipher = Aes256Gcm::new(&key); 
 
     let nonce_array: GenericArray<u8, U12> = GenericArray::clone_from_slice(&iv[..12]);
     let nonce = Nonce::<Aes256Gcm>::from(nonce_array);
     
     let mut full_ciphertext = hex_str_to_bytes(ciphertext_hex);
     let mac_bytes = hex_str_to_bytes(data["mac"].as_str().unwrap());
     full_ciphertext.extend_from_slice(&mac_bytes);
 
     let payload = Payload {
         msg: ciphertext.as_ref(),
         aad: &ephem_pub_key  
     };
 
     let plaintext = match cipher.decrypt(&nonce, payload) {
         Ok(plaintext) => {
             plaintext
         },
         Err(_e) => {
             Vec::new()
         }
     };
     
     let plaintext_string = String::from_utf8_lossy(&plaintext).into_owned();

     // Display the home screen.
     NbglHomeAndSettings::new()
         .glyph(&FERRIS)
         .settings(settings.get_mut(), &settings_strings)
         .infos(
             &plaintext_string, // Display the plaintext
             env!("CARGO_PKG_VERSION"),
             env!("CARGO_PKG_AUTHORS"),
         )
 }
 