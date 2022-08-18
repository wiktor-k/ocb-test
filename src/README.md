# OCB test

This crate illustrates the API usage of OCB cipher from the `openssl`
crate.

Do note that the IV and keys should be secure random bytes. Fixing
this issue is left as an exercise for the reader.

## Usage

Encrypting a file:

    cargo run -- encrypt < a-cypherpunks-manifesto.txt > out

Decrypting a file:

    cargo run -- decrypt < out

During this process the `tag` file is either generated (encryption) or
read and used for validation (decryption).
