use base64::{engine::general_purpose, Engine};
use fernet::Fernet;
use pbkdf2::pbkdf2_hmac;
use rand::{thread_rng, Rng};
use sha2::Sha512;

/// Represents the encrypted form of some bytes. Contains the salt and the data.
pub struct Encrypted {
    salt: [u8; 16],
    data: String,
}

/// `impl Encryptable<T>` struct that can be used to encrypt and decrypt a `Vec<u8>` to an `Encrypted`
/// To encrypt arbitrary structs you can use the `bincode` library to first convert the struct to
/// bytes. You then can encrypt the serialized bytes to an `Encrypted`.
///
/// This is a zero size struct
///
/// # Encryption
/// This by default uses:
/// - **Algorithim**: Fernet ( 32 bit Base64 encoded key )
/// - **Key**: Sha512 480,000 round PBKDF2 HMAC
/// - **Salt**: 16 bit salt
///
/// # Speed
/// This is **VERY** slow on debug builds (`~17s`). In release mode it happens almost instantly (`~0.55s`)
pub struct BytesEncrypter;

/// This trait adds encrypt and decrypt functions to a type, `T`
pub trait Encryptable<T> {
    /// Encrypts `T` with password and returns an result containing an `Encrypted` with the data and salt
    fn encrypt(data: &T, password: &str) -> Result<Encrypted, Box<dyn std::error::Error>>;
    /// Decrypts `Encrypted` with password and returns a result containing `T`
    fn decrypt(data: &Encrypted, password: &str) -> Result<T, Box<dyn std::error::Error>>;
}

impl Encryptable<Vec<u8>> for BytesEncrypter {
    fn encrypt(data: &Vec<u8>, password: &str) -> Result<Encrypted, Box<dyn std::error::Error>> {
        let mut salt = [0u8; 16];
        thread_rng().fill(&mut salt);

        let mut kdf = [0u8; 32];
        pbkdf2_hmac::<Sha512>(&password.as_bytes(), &salt, 480_000, &mut kdf);

        let key = general_purpose::URL_SAFE.encode(&kdf);
        let f = Fernet::new(&key.as_str()).unwrap();
        Ok(Encrypted {
            salt,
            data: f.encrypt(&data),
        })
    }

    fn decrypt(data: &Encrypted, password: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut kdf = [0u8; 32];
        pbkdf2_hmac::<Sha512>(&password.as_bytes(), &data.salt, 480_000, &mut kdf);

        let key = general_purpose::URL_SAFE.encode(&kdf);
        let f = Fernet::new(&key.as_str()).unwrap();
        Ok(f.decrypt(&data.data)?)
    }
}

#[cfg(test)]
mod tests {
    use crate::{BytesEncrypter, Encryptable};

    /// This is **VERY** slow on debug builds (`~17s`). In release mode it happens almost instantly (`~0.55s`)
    #[test]
    fn encryption() {
        const CORRECT_PASSWORD: &str = "password";
        const INCORRECT_PASSWORD: &str = "incorrect password";
        const TEST_DATA: &[u8] = b"test";

        let encrypted = BytesEncrypter::encrypt(&TEST_DATA.to_vec(), CORRECT_PASSWORD).unwrap();
        let d1 = BytesEncrypter::decrypt(&encrypted, CORRECT_PASSWORD);
        let d2 = BytesEncrypter::decrypt(&encrypted, INCORRECT_PASSWORD);

        assert!(&d1.is_ok());
        assert!(&d2.is_err());
        assert_eq!(&d1.unwrap(), TEST_DATA);
    }
}
