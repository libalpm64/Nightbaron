# Nightbaron

Nightbaron is a file encryptor built on **ChaCha20-Poly1305** and **Argon2**.
The main purpose is to make it economically infeasible to bruteforce the encrypted file's key. With Argon2 and 8 GiB of memory as the default, it uses so much memory that even distributed ASICs will struggle with bruteforcing more than 200 hashes per second.

**Features:**

* Custom salt
* Delete original folder after encryption
* Modern UI
* Memory erasure after closure (at runtime)

**License:** GNU Affero General Public License v3.0
