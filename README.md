# cryptographic-primitives
Utilizzo di 
- Diffie-hellman per lo scambio della chiave privata usata per AES (e della chiave per HMAC - non implementato)
- AES-CBC (AES nella modalità Cipher block Chaining) per cifrare il messaggio da inviare, al fine di garantire la confidenzialità
- HMAC per avere autenticazione e integrità del messaggio (tecnica encrypt-then-MAC) (non implementato)
Per garantire nella comunicazione le seguenti proprietà: autenticazione, confidenzialità, non-ripudio e integrità.
