#![no_main]

use libfuzzer_sys::fuzz_target;
use molecule::prelude::{Entity, Reader};
use molecule2::Cursor;
use types_rust::{types_api, types_api2, types_moleculec_check::check_mol};

const ALL_IN_ONE_MIN_SIZE: usize = 1106;

fuzz_target!(|data: &[u8]| {
    let data = if data.len() < ALL_IN_ONE_MIN_SIZE {
        let mut buf = Vec::<u8>::new();
        buf.resize(ALL_IN_ONE_MIN_SIZE, 0);
        buf[0..data.len()].copy_from_slice(data);

        buf
    } else {
        data.to_vec()
    };

    let cursor = Cursor::new(data.len(), Box::new(data.clone()));

    if types_api::AllInOneReader::verify(&data, true).is_err() {
        return;
    }

    let all1 = types_api::AllInOne::new_unchecked(molecule::bytes::Bytes::from(data));
    let all2: types_api2::AllInOne = cursor.into();

    check_mol(&all1, &all2).expect("check mol");
});
