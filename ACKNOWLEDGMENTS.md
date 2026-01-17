# Acknowledgements

"Don't roll your own crypto" they said. So I read the RFCs, studied the papers, and rolled it anyway - but with cheat codes. When the math gets scary, you call for backup.

Some parts are mine: the certificate parsing, the ASN.1 wrangling, the DER encoding nightmares, the verification protocols. Other parts? I knew when to borrow from the masters.

- **[Monocypher](https://github.com/LoupVaillant/Monocypher)** - Loup Vaillant wrote crypto code so clean it makes you question everything you've ever committed. The field arithmetic, the scalar operations, the curve gymnastics - when you need X25519 and Ed25519 done right, you study this. Some of that wisdom lives here now.

- **[digestpp](https://github.com/kerukuro/digestpp)** - A C++11 header-only hash library that just works. SHA-256, SHA-512, BLAKE2b, and more exotic specimens. No dependencies, no drama, no "please install OpenSSL first." The hash implementations tip their hat.

- **[plusaes](https://github.com/kkAyataka/plusaes)** - AES-GCM in a single header. ECB, CBC, CTR, GCM - pick your mode, include the file, done. When you need symmetric encryption without the baggage, this delivers.

The recipe:
1. Build the certificate infrastructure from scratch (X.509 is fun, said no one ever)
2. Implement ASN.1/DER because apparently that's a thing people do
3. Borrow battle-tested primitives for the scary elliptic curve bits
4. Wrap everything in modern C++ with a consistent API
5. Make it header-only because dependencies are for quitters
6. Ship it

The certificate stuff, the verification protocols, the API design - that's on me. The low-level crypto primitives - that's standing on shoulders. If the signatures verify correctly, we all win. If something's broken, check git blame.

*Crypto is hard. Acknowledging your limits is smart. Shipping anyway is... a choice.*
