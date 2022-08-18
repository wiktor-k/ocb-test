use openssl::symm::{Cipher, Crypter, Mode};
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::Path;

fn file_to_vec(p: impl AsRef<Path>) -> std::io::Result<Vec<u8>> {
    let mut f = File::open(&p)?;
    let meta = std::fs::metadata(p)?;
    let mut buffer = vec![0; meta.len() as usize];
    let count = f.read(&mut buffer)?;
    buffer.truncate(count);
    Ok(buffer)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();

    let t = Cipher::aes_128_ocb();
    let key = file_to_vec("key")?;
    let iv = file_to_vec("iv")?;
    let aad = file_to_vec("aad")?;

    let mode = match args[1].as_ref() {
        "encrypt" => Mode::Encrypt,
        "decrypt" => Mode::Decrypt,
        _ => panic!("unknown mode"),
    };

    let mut c = Crypter::new(t, mode, &key, Some(&iv))?;

    let mut tag = vec![0; 16];

    c.set_tag_len(tag.len())?;

    c.aad_update(&aad)?;
    let buf_size = 32;
    let mut data = vec![0; buf_size];
    let mut out = vec![0; buf_size + t.block_size()];
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();

    loop {
        let size = stdin.read(&mut data)?;
        if size == 0 {
            break;
        }
        let count = c.update(&data[..size], &mut out)?;
        stdout.write_all(&out[..count])?;
    }

    if let Mode::Decrypt = mode {
        let tag = file_to_vec("tag")?;
        c.set_tag(&tag)?;
    }

    let rest = c.finalize(&mut out)?;
    stdout.write_all(&out[..rest])?;

    if let Mode::Encrypt = mode {
        c.get_tag(&mut tag)?;
        File::create("tag")?.write_all(&tag)?;
    }
    Ok(())
}
