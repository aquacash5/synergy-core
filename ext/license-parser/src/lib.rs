use ed25519_dalek::PublicKey;
use v3_license_parser::{LicenseType, SignedLicense};

include!(concat!(env!("OUT_DIR"), "/publickey.rs"));

#[cxx::bridge]
mod ffi {
    #[namespace = "shared"]
    struct LicenseData {
        license_type: String,
        expiration_year: u32,
        expiration_month: u32,
        expiration_day: u32,
        user_id: u32,
        perpetual: bool,
        trial: bool,
        valid: bool,
        computer_id: String,
    }

    extern "Rust" {
        fn validate_license(license_str: &str) -> LicenseData;
    }
}

fn type_string(l_type: LicenseType) -> String {
    use LicenseType::*;
    match l_type {
        Basic => "basic".to_owned(),
        Pro => "pro".to_owned(),
        ChinaBasic => "basic_china".to_owned(),
        ChinaPro => "pro_china".to_owned(),
        Business => "business".to_owned(),
    }
}

fn validate_license(license_str: &str) -> ffi::LicenseData {
    if let Ok(result) = validate_license_res(license_str) {
        result
    } else {
        ffi::LicenseData {
            license_type: String::from(""),
            expiration_year: 0,
            expiration_month: 0,
            expiration_day: 0,
            user_id: 0,
            perpetual: false,
            trial: false,
            computer_id: String::from(""),
            valid: false,
        }
    }
}

fn validate_license_res(license_str: &str) -> Result<ffi::LicenseData, Box<dyn std::error::Error>> {
    let verifier: PublicKey = PublicKey::from_bytes(&PUBLIC_KEY)?;
    let signed_license: SignedLicense = license_str.parse()?;
    let license = &signed_license.license;
    if signed_license.verify(verifier) {
        Ok(ffi::LicenseData {
            license_type: type_string(license.license_type),
            expiration_year: license.expiration_year.into(),
            expiration_month: license.expiration_month.into(),
            expiration_day: license.expiration_day.into(),
            user_id: license.user_id,
            perpetual: license.perpetual,
            trial: license.trial,
            computer_id: license.computer_id.clone().unwrap_or_default(),
            valid: true,
        })
    } else {
        Ok(ffi::LicenseData {
            license_type: type_string(license.license_type),
            expiration_year: license.expiration_year.into(),
            expiration_month: license.expiration_month.into(),
            expiration_day: license.expiration_day.into(),
            user_id: license.user_id,
            perpetual: license.perpetual,
            trial: license.trial,
            computer_id: license.computer_id.clone().unwrap_or_default(),
            valid: false,
        })
    }
}
