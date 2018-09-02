#[cfg(test)]
#[macro_use] extern crate hex_literal;

extern crate digest;
use digest::Digest;
use digest::generic_array::GenericArray;

use std::io::{self, Read, Write, ErrorKind};

const DEFAULT_BUF_SIZE: usize = 4 * 1024;

pub fn copy_and_hash<R: ?Sized, W: ?Sized, H>(reader: &mut R, writer: &mut W) -> io::Result<(u64, GenericArray<u8, H::OutputSize>)>
    where R: Read, W: Write, H: Digest
{
    let mut buf = [0; DEFAULT_BUF_SIZE];
    let mut hasher = H::new();

    let mut written = 0;
    loop {
        let len = match reader.read(&mut buf) {
            Ok(0) => return Ok((written, hasher.result())),
            Ok(len) => len,
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        hasher.input(&buf[..len]);
        writer.write_all(&buf[..len])?;
        written += len as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::copy_and_hash;
    extern crate sha2;

    #[test]
    fn test_copies_small_things() {
        let result = hex!("26c6394cd46693652def622def991758b4c611c4029c2e47dc8c6504f4be600f");
        let len = 17;
        let input = "butts butts butts";
        let mut output = vec![];

        let ret = copy_and_hash::<_, _, sha2::Sha256>(&mut input.as_bytes(), &mut output).unwrap();
        assert_eq!(ret.0, len);
        assert_eq!(ret.1.as_slice(), result);
        assert_eq!(String::from_utf8(output).unwrap(), input);
    }
}
