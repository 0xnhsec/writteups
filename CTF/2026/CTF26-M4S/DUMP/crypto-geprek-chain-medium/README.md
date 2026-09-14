# 🐔 GeprekChain

Selamat datang di **GeprekChain**, blockchain paling gurih se-nusantara!

Konon salah satu blok menyimpan potongan-potongan sebuah rahasia. Tapi hati-hati,
tidak semua yang tampak di permukaan itu benar. Di dunia blockchain, **masa lalu
mengunci masa kini** — tiap blok dijaga oleh blok sebelum-sebelumnya.

## Berkas

- `chain.json` — dump lengkap seluruh blok pada rantai.

## Tujuan

Rekonstruksi flag dengan format `REDLIMIT{...}`.

## Petunjuk

1. Sebuah blockchain yang baik itu **konsisten** — pastikan setiap blok sungguh
   valid sebelum kamu percaya isinya.
2. Field `data` tiap blok tidaklah polos. Ia terkunci oleh sesuatu milik
   tetangganya.
3. `base64`, `XOR`, dan `sha256` adalah teman baikmu.
4. Blok pertama (genesis) suka bercanda. Jangan mudah tertipu.

Selamat ngoprek! 🌶️
