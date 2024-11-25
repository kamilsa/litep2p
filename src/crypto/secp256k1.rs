// Copyright 2019 Parity Technologies (UK) Ltd.
// Copyright 2023 litep2p developers
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! Secp256k1 keys.

use crate::{error::Error, PeerId};

// use secp256k1::{self as secp256k1, Secp256k1, SecretKey as Secp256k1SecretKey, PublicKey as Secp256k1PublicKey, Message, ecdsa::Signature as Signature};
use libsecp256k1::{Message, PublicKey as Secp256k1PublicKey, SecretKey as Secp256k1SecretKey, Signature};
use sha2::{Digest as ShaDigestTrait, Sha256};
use rand::RngCore;
use zeroize::Zeroize;

use std::{cmp, convert::TryFrom, fmt};

/// A Secp256k1 keypair.
pub struct Keypair {
    secret: Secp256k1SecretKey,
    public: Secp256k1PublicKey,
}

impl Keypair {
    /// Generate a new random Secp256k1 keypair.
    pub fn generate() -> Keypair {
        let secret = libsecp256k1::SecretKey::random(&mut rand::thread_rng());
        let public = libsecp256k1::PublicKey::from_secret_key(&secret);
        Keypair { secret, public }
    }

    /// Encode the keypair into a byte array.
    pub fn encode(&self) -> Vec<u8> {
        let mut kp = self.secret.serialize().to_vec();
        kp.extend_from_slice(&self.public.serialize());
        kp
    }

    /// Decode a keypair from a byte array.
    pub fn decode(kp: &[u8]) -> crate::Result<Keypair> {
        if kp.len() != 32+65 {
            return Err(Error::Other("Invalid keypair length".to_string()));
        }
        let kp = kp.to_vec();
        
        let secret = Secp256k1SecretKey::parse_slice(&kp[..32])
            .map_err(|error| Error::Other(format!("Failed to parse keypair: {error:?}")))?;
        let public = Secp256k1PublicKey::parse_slice(&kp[32..], None)
            .map_err(|error| Error::Other(format!("Failed to parse keypair: {error:?}")))?;
        Ok(Keypair { secret, public })
    }

    /// Sign a message using the private key of this keypair.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let generic_array = Sha256::digest(msg);
        let mut array = [0u8; 32];
        array.copy_from_slice(generic_array.as_slice());
        let message = Message::parse(&array);
        libsecp256k1::sign(&message, &self.secret).0.serialize_der().as_ref().into()
    }

    /// Get the public key of this keypair.
    pub fn public(&self) -> PublicKey {
        PublicKey(self.public)
    }

    /// Get the secret key of this keypair.
    pub fn secret(&self) -> SecretKey {
        SecretKey(self.secret)
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair").field("public", &self.public).finish()
    }
}

impl Clone for Keypair {
    fn clone(&self) -> Keypair {
        Keypair {
            secret: self.secret.clone(),
            public: self.public.clone(),
        }
    }
}

/// Demote a Secp256k1 keypair to a secret key.
impl From<Keypair> for SecretKey {
    fn from(kp: Keypair) -> SecretKey {
        SecretKey(kp.secret)
    }
}

/// Promote a Secp256k1 secret key into a keypair.
impl From<SecretKey> for Keypair {
    fn from(sk: SecretKey) -> Keypair {
        let public = Secp256k1PublicKey::from_secret_key(&sk.0);
        Keypair { secret: sk.0, public }
    }
}

/// A Secp256k1 public key.
#[derive(Eq, Clone)]
pub struct PublicKey(Secp256k1PublicKey);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicKey(compressed): ")?;
        for byte in self.0.serialize().iter() {
            write!(f, "{byte:x}")?;
        }
        Ok(())
    }
}

impl cmp::PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.serialize().eq(&other.0.serialize())
    }
}

impl PublicKey {
    /// Verify the Secp256k1 signature on a message using the public key.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        self.verify_hash(Sha256::digest(msg).as_ref(), sig)
    }

    /// Verify the Secp256k1 DER-encoded signature on a raw 256-bit message using the public key.
    pub fn verify_hash(&self, msg: &[u8], sig: &[u8]) -> bool {
        Message::parse_slice(msg)
            .and_then(|m| Signature::parse_der(sig).map(|s| libsecp256k1::verify(&m, &s, &self.0)))
            .unwrap_or(false)
    }

    /// Encode the public key into a byte array.
    pub fn encode(&self) -> Vec<u8> {
        self.0.serialize().to_vec()
    }

    /// Decode a public key from a byte array.
    pub fn decode(k: &[u8]) -> crate::Result<PublicKey> {
        Secp256k1PublicKey::parse_slice(k, None)
            .map_err(|error| Error::Other(format!("Failed to parse keypair: {error:?}")))
            .map(PublicKey)
    }

    /// Convert public key to `PeerId`.
    pub fn to_peer_id(&self) -> PeerId {
        crate::crypto::PublicKey::Secp256k1(self.clone()).into()
    }
}

/// A Secp256k1 secret key.
pub struct SecretKey(Secp256k1SecretKey);

// /// View the bytes of the secret key.
// impl AsRef<[u8]> for SecretKey {
//     fn as_ref(&self) -> &[u8] {
//         std::convert::Into::<Scalar>::into(self.0).b32()
//     }
// }

impl Clone for SecretKey {
    fn clone(&self) -> SecretKey {
        SecretKey(self.0.clone())
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey")
    }
}

impl SecretKey {
    /// Generate a new Secp256k1 secret key.
    pub fn generate() -> SecretKey {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        SecretKey(
            Secp256k1SecretKey::parse_slice(&bytes).expect(
                "this returns `Err` only if the length is wrong; the length is correct; qed",
            ),
        )
    }

    /// Create a Secp256k1 secret key from a byte slice.
    pub fn from_bytes(sk_bytes: &[u8]) -> crate::Result<SecretKey> {
        Secp256k1SecretKey::parse_slice(sk_bytes)
            .map_err(|error| Error::Other(format!("Failed to parse keypair: {error:?}")))
            .map(SecretKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::*;

    fn eq_keypairs(kp1: &Keypair, kp2: &Keypair) -> bool {
        kp1.secret.serialize() == kp2.secret.serialize() && kp1.public == kp2.public
    }

    #[test]
    fn secp256k1_keypair_encode_decode() {
        fn prop() -> bool {
            let kp1 = Keypair::generate();
            let kp1_enc = kp1.encode();
            let kp2 = Keypair::decode(&kp1_enc).unwrap();
            eq_keypairs(&kp1, &kp2)
        }
        QuickCheck::new().tests(10).quickcheck(prop as fn() -> _);
    }

    #[test]
    fn secp256k1_keypair_from_secret() {
        fn prop() -> bool {
            let kp1 = Keypair::generate();
            let sk = kp1.secret();
            let kp2 = Keypair::from(sk);
            eq_keypairs(&kp1, &kp2)
        }
        QuickCheck::new().tests(10).quickcheck(prop as fn() -> _);
    }

    #[test]
    fn secp256k1_signature() {
        let kp = Keypair::generate();
        let pk = kp.public();

        let msg = "hello world".as_bytes();
        let sig = kp.sign(msg);
        assert!(pk.verify(msg, &sig));

        let mut invalid_sig = sig.clone();
        invalid_sig[3..6].copy_from_slice(&[10, 23, 42]);
        assert!(!pk.verify(msg, &invalid_sig));

        let invalid_msg = "h3ll0 w0rld".as_bytes();
        assert!(!pk.verify(invalid_msg, &sig));
    }

    #[test]
    fn secret_key() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();

        let key = Keypair::generate();
        tracing::trace!("keypair: {:?}", key);
        tracing::trace!("secret: {:?}", key.secret());
        tracing::trace!("public: {:?}", key.public());

        let new_key = Keypair::from(key.secret());
        assert!(new_key.secret().0 == key.secret().0);
        assert!(new_key.public() == key.public());

        let new_secret = SecretKey::from(new_key.clone());
        assert!(new_secret.0 == new_key.secret().0);

        let cloned_secret = new_secret.clone();
        assert!(cloned_secret.0 == new_secret.0);
    }
}