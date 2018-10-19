#[cfg(test)]
#[macro_use] extern crate hex_literal;

extern crate digest;
use digest::Digest;
use digest::generic_array::GenericArray;

use std::io::{self, Read, Write, ErrorKind};

const DEFAULT_BUF_SIZE: usize = 4 * 1024 * 1024;

/// Copy data from `reader` to `writer`, along the way hashing using `H` which must implement
/// Digest. Return value is the same as for `std::io::copy` except that it returns a 2 tuple of the
/// bytes copied, and the hash value, or an `io::Error`.
///
/// ```rust
/// # extern crate sha2;
/// # extern crate hashing_copy;
/// # use hashing_copy::copy_and_hash;
/// use std::io;
/// use sha2::Sha256;
///
/// let mut reader: &[u8] = b"hello world";
/// let mut writer: Vec<u8> = vec![];
///
/// let (bytes_copied, hash) = copy_and_hash::<_, _, Sha256>(&mut reader, &mut writer)
///                                 .expect("Couldn't copy data");
///
/// assert_eq!(11, bytes_copied);
/// assert_eq!(&b"hello world"[..], &writer[..]);
/// assert_eq!(hash[..=8], [0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5]);
/// ```

pub fn copy_and_hash<R: ?Sized, W: ?Sized, H>(reader: &mut R, writer: &mut W) -> io::Result<(u64, GenericArray<u8, H::OutputSize>)>
    where R: Read, W: Write, H: Digest
{
    let mut buf = vec![0; DEFAULT_BUF_SIZE];
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
    use std::fs::File;

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

    #[test]
    fn test_copies_large_things() {
        let result = hex!("87bcb5058da1531811646857b8d5684429480ef938fd0b143408c42c2fe8e974");
        let len = 84084;
        let mut input = File::open("test/many_butts").unwrap();
        let mut output = vec![];

        let ret = copy_and_hash::<_, _, sha2::Sha256>(&mut input, &mut output).unwrap();
        assert_eq!(ret.0, len);
        assert_eq!(ret.1.as_slice(), result);
    }

    #[test]
    fn test_copies_things_spanning_multiple_blocks() {
        let result = hex!("4c34caef17ee3d709ea9f3c964a79722f79118cd00869a340c3bdf1bb38375c3");
        let len = 7020351;
        let mut input = File::open("test/extremely_many_butts").unwrap();
        let mut output = vec![];

        let ret = copy_and_hash::<_, _, sha2::Sha256>(&mut input, &mut output).unwrap();
        assert_eq!(ret.0, len);
        assert_eq!(ret.1.as_slice(), result);
    }
}
