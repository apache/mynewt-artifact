# Mynewt Images

## Anatomy

```
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            Header                             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ~                      Padding (optional)                       ~
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ~                                                               ~
    ~                                                               ~
    ~                             Body                              ~
    ~                                                               ~
    ~                                                               ~
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                 Protected Trailer (optional)                  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ~                                                               ~
    ~                   Protected TLVs (optional)                   ~
    ~                                                               ~
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            Trailer                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ~                                                               ~
    ~                             TLVs                              ~
    ~                                                               ~
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

All fields are in host-byte order (typically little endian).

### Header

```
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Magic (0x96f3b83d)                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     Reserved1 (0x00000000)                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Header size          |        Protected size         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           Body size                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             Flags                             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Major version | Minor version |           Revision            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Build number                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     Reserved2 (0x00000000)                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Description | Notes |
| ----- | ----------- | ----- |
| Magic | Identifies the start of an image | |
| Header size | 32 + the amount of padding that follows the header | |
| Protected size | Size, in bytes, of the protected trailer PLUS the protected TLVs | 0 if no protected TLVs |
| Body size | Size, in bytes, of the image body | |
| Flags | One bit per flag | See below |
| Major version | The first element of the version number | major.minor.revision.build |
| Minor version | The second element of the version number | major.minor.revision.build |
| Revision      | The third element of the version number | major.minor.revision.build |
| Build number  | The fourth element of the version number | No meaning in semver |

### Body

The executable itself.  In encrypted images, this is the encrypted portion.

### Protected trailer

Describes the set of protected TLVs that follow.  This trailer is NOT present if there are no protected TLVs.

```
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |        Magic (0x6908)         |        Protected size         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Description | Notes |
| ----- | ----------- | ----- |
| Magic | Identifies the start of the protected trailer | |
| Protected size | Size, in bytes, of the protected trailer PLUS the protected TLVs | Identical to "Protected size" in image header |

### Protected TLVs

A sequence of TLV structures (see "TLVs" section for specifics).  The structure of these TLVs is identical to the non-protected TLVs.  The difference is that these TLVs are included as input to the image hash.

### Trailer

Describes the set of TLVs that follow.  This trailer is always present.

```
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |        Magic (0x6907)         |             Size              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Description | Notes |
| ----- | ----------- | ----- |
| Magic | Identifies the start of the trailer | |
| Size | Size, in bytes, of the trailer PLUS the TLVs | |

### TLVs

The TLVs (type-length-value) are a sequence of variable length structures containing image metadata.

```
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      | Reserved (00) |            Length             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ~                                                               ~
    ~                             Body                              ~
    ~                                                               ~
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```


| Field | Description | Notes |
| ----- | ----------- | ----- |
| Type | Identifies the type of data in the TLV body | |
| Length | The length, in bytes, of the TLV body | |
| Body | Varies by type | |

## Header flags

Each header flag is represented by a single bit.  As with the other numeric fields, the flags field is in host byte order. 

| Value | Description | Notes |
| ----- | ----------- | ----- |
| 0x00000004 | Encrypted by key in TLV | Implies the presence of an "enc" TLV |
| 0x00000010 | Non-bootable | Second half of a split image |

## TLV types

| Value | Description | Notes |
| ----- | ----------- | ----- |
| 0x01  | Key hash | SHA256 of image verification key |
| 0x10  | SHA256 | SHA256 of parts of the image (see below) |
| 0x20  | Signature: RSA2048 | |
| 0x21  | Signature: ECDSA224 | |
| 0x22  | Signature: ECDSA256 | |
| 0x23  | Signature: RSA3072 | |
| 0x24  | Signature: ED25519 | |
| 0x30  | Key-encrypting key: RSA | |
| 0x31  | Key-encrypting key: KEK | |
| 0x32  | Key-encrypting key: EC256 | |
| 0x50  | Encryption nonce | |
| 0x60  | Secret index | Indicates hardware-specific location of encryption key |

### SHA256

The sha256 is calculated using the following inputs:

* Header
* Post-header padding
* Unencrypted image body
* Protected trailer (if present)
* Protected TLVs (if present)
