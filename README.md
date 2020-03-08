# JSON Web Encryption (JWE)

This library allows to use JSON Web Encryption (JWE) represents encrypted content using JSON based data structures [RFC7159]. The JWE cryptographic mechanisms encrypt and provide integrity protection for an arbitrary sequence of octets.

## Requirements

Add the following dependencies in the build.gradle:

```sh
    Kotlin: 1.3+
```

Add the following maven url in the build.gradle of the project inside "repositories":

```sh
    repositories {
        google()
        jcenter()
        maven {
            url "https://dl.bintray.com/camoal/maven"
        }
    }
```

Add the following dependency to the application gradle.

```sh
    dependencies {
        ...
        implementation 'com.camoal.jwe:jwe:1.0.0'
    }
```

## Usage

Create JWE using RSA-OAEP. If the algorithm is not defined, RSA-OAEP is always used by default:

```sh
    val jwe = Jwe.Builder()
        .algorithm(Algorithm.RSA_OAEP)
        .publicKey(publicKey)
        .payload("Hello world!")
        .build()
```

Create JWE using RSA-OAEP-256:

```sh
    val jwe = Jwe.Builder()
        .algorithm(Algorithm.RSA_OAEP_256)
        .publicKey(publicKey)
        .payload("Hello world!")
        .build()
```

Create JWE using RSA-OAEP with X.509 Certificate SHA-256 Thumbprint

```sh
    val jwe = Jwe.Builder()
        .certificate(x509Certificate)
        .payload("Hello world!")
        .build()
```

Decode Header Parameters:

```sh
    val header = Jwe.Parser()
        .jwe(jwe)
        .headerParameters()
```

Decode JWE:

```sh
    val jweDecoded = Jwe.Parser()
        .privateKey(privateKey)
        .json(jwe)
        .parse()
```
