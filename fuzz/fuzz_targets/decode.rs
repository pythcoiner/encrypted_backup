#![no_main]

extern crate encrypted_backup;
use encrypted_backup::ll::decode_v1;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|d: &[u8]| {
    let _ = decode_v1(d);
});
