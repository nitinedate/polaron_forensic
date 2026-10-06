# Public synthetic WhatsApp CRYPT fixtures

These inputs and matching keys are deliberately synthetic and public. Formats: original .crypt plus CRYPT5/7/8/9/10/11/12/14/15; fourteen encrypted files; SQLite, ZIP, JSON, image and binary payloads. The fixture manifest records expected hashes and the known test secrets. Never use these keys as production secrets.

From the project root run `python scripts/test-whatsapp-decryption.py --out C:/Aetheris-QA/whatsapp-case-1` using a new empty output folder. Expected: status=passed, 12 checks. The script generates its own equivalent inputs and validates recovered chats, a surviving deleted row, attachment references, RAG text, unchanged originals and keyless rejection.

For these prebuilt inputs, follow `WHATSAPP-CRYPT-RELEASE.md`. The supplied 158-byte `data/data/com.whatsapp/files/key` contains the CRYPT14 test secret at bytes 126 through 157. This is key-file extraction; ciphertext alone cannot yield a matching key. Other installations/backups require their own matching material. The CRYPT5 fixture's original Google account is `whatsapp-qa@example.test`.

Independent fixture generation: `scripts/whatsapp_qa_fixtures.py`. A separate `WhatsApp-CRYPT-Test-Cases.zip` supplies a runnable minimal QA subset with dependency pins and Windows launcher. The complete deployable application remains this project.
