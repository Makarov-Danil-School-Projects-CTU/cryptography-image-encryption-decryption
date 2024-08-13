Keywords: C++, Open SSL

# 📝 Task Objective:

Your task is to implement two (or more) functions (not a full program) that can encrypt and decrypt an image file in TGA format.<br>
For the purpose of this task, we will consider a simplified form of the image:
- Mandatory Header: 18 bytes - these bytes are not modified, just copied into the encrypted image.
- Optional Header: The size is calculated from the mandatory header - this part of the header will be treated as image data, i.e., encrypted together with the image data without any changes.
- Image Data: The rest of the file.

### 📥 Function Parameters:

```
bool encrypt_data(const string &in_filename, const string &out_filename, crypto_config &config)

```

**in_filename:** Input file name.<br>
**out_filename:** Output file name.<br>
**config:** A data structure crypto_config described below.<br>
**Return value:** true in case of success, false otherwise. Failure occurs if the file is invalid in some way (missing mandatory header, cannot open, read, write, etc.), or if the invalid configuration of crypto_config cannot be corrected.

```
bool decrypt_data(const string &in_filename, const string &out_filename, crypto_config &config)
```

Uses the same interface as encrypt_data, but performs the inverse operation relative to encryption. The mandatory part of the header is copied (not encrypted), and the rest of the file is decrypted in the same way it was encrypted. In this case, we expect a valid decryption key and IV (if needed) to be provided. If these parameters are missing, the data cannot be decrypted, and the function should return false.

### 🛠️ Data Structure:

**crypto_config** contains:
1. The selected block cipher, specified by its name.
2. The secret encryption key and its size.
3. The initialization vector (IV) and its size.

### 🔒 Encryption Considerations:

During encryption, the following problem may occur: if the encryption key (or IV) is insufficient (i.e., their length is not at least as long as required by the selected block cipher, or they are completely missing), they must be securely generated. If the selected block cipher does not require an IV (and thus one is not provided), do not generate a new IV! Be sure to store any generated keys and IVs in the provided config structure.
