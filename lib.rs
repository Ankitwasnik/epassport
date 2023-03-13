#![cfg_attr(not(feature = "std"), no_std)]

#[ink::contract]
mod epassport {

    /*
        Functions:
        1. Store a certificate from CSCA
            - Store country wise certificates
        2. Store DSO and DSC
        3. Vaidate DSO and DSC
        4. Get a certificate
        5. Get DSO and DSC
    */

    /// Defines the storage of your contract.
    /// Add new fields to the below struct in order
    /// to add new static storage fields to your contract.
    #[ink(storage)]
    pub struct Epassport {}

    impl Epassport {

        #[ink(constructor)]
        pub fn new() -> Self {
            Self {}
        }

        #[ink(message)]
        pub fn recover_public_key(&self, signature: [u8; 65], message_hash: [u8; 32]) -> [u8; 33] {
            let res = self.env().ecdsa_recover(&signature, &message_hash);
            return res.unwrap();
        }

        #[ink(message)]
        pub fn is_valid_signature(
            &self,
            signature: [u8; 65],    /*dso signature*/
            message_hash: [u8; 32], /* message_digest */
            public_key: [u8; 33],   /* dsc*/
        ) -> bool {
            let res = self.env().ecdsa_recover(&signature, &message_hash);
            if res.is_err() {
                return false;
            }
            let recovered_public_key = res.unwrap();
            return recovered_public_key == public_key;
        }

        
        #[ink(message)]
        pub fn validate_cert(&self, dsc_cert_bytes: Vec<u8>, csca_cert_bytes: Vec<u8>) -> bool {
            let dsc = x509_signature::parse_certificate(&dsc_cert_bytes).unwrap();
            let csca = x509_signature::parse_certificate(&csca_cert_bytes).unwrap();
            let res = dsc.check_issued_by(&csca);
            return res.is_ok();
        }

    }

    /// Unit tests in Rust are normally defined within such a `#[cfg(test)]`
    /// module and test functions are marked with a `#[test]` attribute.
    /// The below code is technically just normal Rust code.
    #[cfg(test)]
    mod tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;

        const SIGNATURE: [u8; 65] = [
            195, 218, 227, 165, 226, 17, 25, 160, 37, 92, 142, 238, 4, 41, 244, 211, 18, 94, 131,
            116, 231, 116, 255, 164, 252, 248, 85, 233, 173, 225, 26, 185, 119, 235, 137, 35, 204,
            251, 134, 131, 186, 215, 76, 112, 17, 192, 114, 243, 102, 166, 176, 140, 180, 124, 213,
            102, 117, 212, 89, 89, 92, 209, 116, 17, 28,
        ];
        const MESSAGE_HASH: [u8; 32] = [
            167, 124, 116, 195, 220, 156, 244, 20, 243, 69, 1, 98, 189, 205, 79, 108, 213, 78, 65,
            65, 230, 30, 17, 37, 184, 220, 237, 135, 1, 209, 101, 229,
        ];
        const EXPECTED_COMPRESSED_PUBLIC_KEY: [u8; 33] = [
            3, 110, 192, 35, 209, 24, 189, 55, 218, 250, 100, 89, 40, 76, 222, 208, 202, 127, 31,
            13, 58, 51, 242, 179, 13, 63, 19, 22, 252, 164, 226, 248, 98,
        ];

        #[ink::test]
        fn recover_public_key_works() {
            let epassport = Epassport::new();
            let result = epassport.recover_public_key(SIGNATURE, MESSAGE_HASH);
            assert_eq!(result, EXPECTED_COMPRESSED_PUBLIC_KEY);
        }

        #[ink::test]
        fn should_return_true_for_valid_signature() {
            let epassport = Epassport::new();
            let result = epassport.is_valid_signature(
                SIGNATURE,
                MESSAGE_HASH,
                EXPECTED_COMPRESSED_PUBLIC_KEY,
            );
            assert_eq!(true, result)
        }

        #[ink::test]
        fn should_return_false_for_invalid_signature() {
            let epassport = Epassport::new();
            let mut incorrect_signature = SIGNATURE;
            incorrect_signature[0] = SIGNATURE[0] + 10;
            let result = epassport.is_valid_signature(
                incorrect_signature,
                MESSAGE_HASH,
                EXPECTED_COMPRESSED_PUBLIC_KEY,
            );
            assert_eq!(false, result);
        }

        #[ink::test]
        fn should_validate_example_cert() {
            let epassport = Epassport::new();
            let dsc = include_bytes!("./test/dsc.crt").to_vec();
            let ca = include_bytes!("./test/ca.crt").to_vec();
            let is_valid = epassport.validate_cert(
                dsc,
                ca
            );
            assert_eq!(true, is_valid);
        }

        #[ink::test]
        fn should_validate_local_cert() {
            let epassport = Epassport::new();
            let dsc = include_bytes!("./test/local_intermediate.crt").to_vec();
            let ca = include_bytes!("./test/local_ca.crt").to_vec();
            let is_valid = epassport.validate_cert(
                dsc,
                ca
            );
            assert_eq!(true, is_valid);
        }

        #[ink::test]
        fn should_return_false_for_incorrect_ca() {
            let epassport = Epassport::new();
            let dsc = include_bytes!("./test/local_intermediate.crt").to_vec();
            let ca = include_bytes!("./test/ca.crt").to_vec();
            let is_valid = epassport.validate_cert(
                dsc,
                ca
            );
            assert_eq!(false, is_valid);
        }

    }
}
