use ed25519_dalek::PublicKey;
use v3_license_parser::SignedLicense;

include!(concat!(env!("OUT_DIR"), "/publickey.rs"));

#[cxx::bridge]
mod ffi {
    #[namespace = "shared"]
    struct LicenseData {
        license_type: u32,
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

fn validate_license(license_str: &str) -> ffi::LicenseData {
    if let Ok(result) = validate_license_res(license_str) {
        result
    } else {
        ffi::LicenseData {
            license_type: 0,
            expiration_year: 0,
            expiration_month: 0,
            expiration_day: 0,
            user_id: 0,
            perpetual: false,
            trial: false,
            computer_id: "".to_string(),
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
            license_type: license.license_type.to_byte().into(),
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
            license_type: license.license_type.to_byte().into(),
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
