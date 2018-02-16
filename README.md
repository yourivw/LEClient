# LEClient
PHP LetsEncrypt client library for ACME v2. The aim of this client is to make an easy-to-use and integrated solution to create a LetsEncrypt-issued SSL/TLS certificate with PHP. The user has to have access to the web server or DNS management to be able to verify the domain is accessible/owned by the user.

## Current version

The current version is 1.1.0

This client was developed with the use of the LetsEncrypt staging server for version 2. While version 2 is still being developed and implemented by LetsEncrypt at this moment, the project might be subject to change.

## Getting Started

These instructions will get you started with this client library. Is you have any questions or find any problems, feel free to open an issue and I'll try to have a look at it.

Also have a look at the [LetsEncrypt documentation](https://letsencrypt.org/docs/) for more information and documentation on LetsEncrypt and ACME.

### Prerequisites

The minimum required PHP version is 7.1.0 due to the implementation of ECDSA. Version 1.0.0 does still work with PHP 5.2 since it is not yet compatible with ECDSA, and will be kept available, but will not be maintained.

This client also depends on cURL and OpenSSL.

### Installing

Download and install the LEClient folder and examples wherever you want to install it. You can include the library by adding the following:
```php
require_once('LEClient/LEClient.php');
```

It is advisable to cut the script some slack regarding execution time by setting a higher maximum time. There are several ways to do so. One it to add the following to the top of the page:
```php
ini_set('max_execution_time', 120); // Maximum execution time in seconds.
```

## Usage

The basic functions and its necessary arguments are shown here. An extended description is included in each class.

<br />

Initiating the client:
```php
$client = new LEClient($email);                               // Initiating a basic LEClient with an array of string e-mail address(es).
$client = new LEClient($email, true);                         // Initiating a LECLient and use the LetsEncrypt staging URL.
$client = new LEClient($email, true, LEClient::LOG_STATUS);   // Initiating a LEClient and log status messages (LOG_DEBUG for full debugging).
```
The client will automatically create a new account if there isn't one found. It will forward the e-mail address(es) supplied during initiation, as shown above.

<br />

Using the account functions:
```php
$acct = $client->getAccount();  // Retrieves the LetsEncrypt Account instance created by the client.
$acct->updateAccount($email);   // Updates the account with new contact information. Supply an array of string e-mail address(es).
$acct->changeAccountKeys();     // Generates a new RSA keypair for the account and updates the keys with LetsEncrypt.
$acct->deactivateAccount();     // Deactivates the account with LetsEncrypt.
```
<br />

Creating a certificate order instance. If there is an order found, stored locally, it will use this order. Otherwise, it will create a new order. If the supplied domain names don't match the order, a new order is created as well. The construction of the LetsEncrypt Order instance:
```php
$order = $client->getOrCreateOrder($basename, $domains);                          			// Get or create order. The basename is preferably the top domain name. This will be the directory in which the keys are stored. Supply an array of string domain names to create a certificate for.
$order = $client->getOrCreateOrder($basename, $domains, $keyType);              			// Get or create order. keyType can be set to "ec" to get ECDSA certificate. "rsa" is default value.
$order = $client->getOrCreateOrder($basename, $domains, $keyType, $notBefore);              // Get or create order. Supply a notBefore date as a string similar to 0000-00-00T00:00:00Z (yyyy-mm-dd hh:mm:ss).
$order = $client->getOrCreateOrder($basename, $domains, $keyType, $notBefore, $notAfter);   // Get or create order. Supply a notBefore and notAfter date as a string similar to 0000-00-00T00:00:00Z (yyyy-mm-dd hh:mm:ss).
```
<br />

Using the order functions:
```php
$valid      = $order->allAuthorizationsValid();                             // Check whether all authorizations in this order instance are valid.
$pending    = $order->getPendingAuthorizations($type);                      // Get an array of pending authorizations. Performing authorizations is described further on. Type is LEOrder::CHALLENGE_TYPE_HTTP or LEOrder::CHALLENGE_TYPE_DNS.
$verify     = $order->verifyPendingOrderAuthorization($identifier, $type);  // Verify a pending order. The identifier is a string domain name. Type is LEOrder::CHALLENGE_TYPE_HTTP or LEOrder::CHALLENGE_TYPE_DNS.
$deactivate = $order->deactivateOrderAuthorization($identifier);            // Deactivate an authorization. The identifier is a string domain name.
$finalize   = $order->finalizeOrder();                                      // Finalize the order and generate a Certificate Signing Request automatically.
$finalize   = $order->finalizeOrder($csr);                                  // Finalize the order with a custom Certificate Signing Request string.
$finalized  = $order->isFinalized();                                        // Check whether the order is finalized.
$cert       = $order->getCertificate();                                     // Retrieves the certificate and stores it in the keys directory, under the specific order (basename).
$revoke     = $order->revokeCertificate();                                  // Revoke the certificate without a reason.
$revoke     = $order->revokeCertificate($reason);                           // Revoke the certificate with a reason integer as found in section 5.3.1 of RFC5280.
```
<br />

Supportive functions:
```php
LEFunctions::RSAGenerateKeys($directory, $privateKeyFile, $publicKeyFile);  // Generate a RSA keypair in the given directory. Variables privateKeyFile and publicKeyFile are optional and have default values private.pem and public.pem.
LEFunctions::ECGenerateKeys($directory, $privateKeyFile, $publicKeyFile);  	// Generate a EC keypair in the given directory (PHP 7.1+ required). Variables privateKeyFile and publicKeyFile are optional and have default values private.pem and public.pem.
LEFunctions::Base64UrlSafeEncode($input);                                   // Encode the input string as a base64 URL safe string.
LEFunctions::Base64UrlSafeDecode($input);                                   // Decode a base64 URL safe encoded string.
LEFunctions::log($data, $function);                                         // Print the data. The function variable is optional and defaults to the calling function's name.
LEFunctions::checkHTTPChallenge($domain, $token, $keyAuthorization);        // Checks whether the HTTP challenge is valid. Performing authorizations is described further on.
LEFunctions::checkDNSChallenge($domain, $DNSDigest);                        // Checks whether the DNS challenge is valid. Performing authorizations is described further on.
LEFunctions::createhtaccess($directory);									// Created a simple .htaccess file in the directory supplied, denying all visitors.
```

## Authorization challenges

LetsEncrypt (ACME) performs authorizations on the domains you want to include on your certificate, to verify you actually have access to the specific domain. Therefore, when creating an order, an authorization is added for each domain. If a domain has recently (in the last 30 days) been verified by your account, for example in another order, you don't have to verify again. At this time, a domain can be verified by a HTTP request to a file (http-01) or a DNS TXT record (dns-01). The client supplies the necessary data for the chosen verification by the call to getPendingAuthorizations(). Since creating a file or DNS record differs for every server, this is not implemented in the client. After the user has fulfilled the challenge requirements, a call has to be made to verifyPendingOrderAuthorization(). This client will first verify the challenge with checkHTTPChallenge() or checkDNSChallenge() by itself, before it is starting the verification by LetsEncrypt. Keep in mind, a wildcard domain can only be verified with a DNS challenge. An example for both challenges is shown below.

### HTTP challenge

For this example, we assume there is one domain left to verify.
```php
$pending = $order->getPendingAuthorizations(LEOrder::CHALLENGE_TYPE_HTTP);
```
This returns an array:
```
Array
(
    [0] => Array
        (
            [type] => http-01
            [identifier] => test.example.org
            [filename] => A8Q1DAVcd_k_oKAC0D_y4ln2IWrRX51jmXnR9UMMtOb
            [content] => A8Q1DAVcd_k_oKAC0D_y4ln2IWrRX51jmXnR9UMMtOb.C4kIiiwfcynb3i48AQVtZRtNrD51z4JiIrdQsgVqcL8
        )
)
```
For a successful verification, a request will be made to the following URL:
```
http://test.example.org/.well-known/acme-challenge/A8Q1DAVcd_k_oKAC0D_y4ln2IWrRX51jmXnR9UMMtOb
```
The content of this file should be set to the content in the array above. The user should create this file before it can verify the authorization.

### DNS challenge

For this example, we assume there are two domains left to verify. One is a wildcard domain. The second domain in this example is added for demonstration purposes. Adding a subdomain to the certificate which is also already covered by the wildcard domain is does not offer much added value.
```php
$pending = $order->getPendingAuthorizations(LEOrder::CHALLENGE_TYPE_DNS);
```
This returns an array:
```
Array
(
    [0] => Array
        (
            [type] => dns-01
            [identifier] => example.org
            [DNSDigest] => FV5HgbpjIYe1x9MkPI81Nffo2oA-Jo2S88gCL7-Ky5P
        )     
    [1] => Array
        (
            [type] => dns-01
            [identifier] => test.example.org
            [DNSDigest] => WM5YIsgaZQv1b9DbRZ81EwCf2fi-Af2JlgxTC7-Up5D
        )
)
```
For a successful verification, DNS records should be created as follows:

| Name                              | TTL | Type | Value                                       |
| --------------------------------- | --- | ---- | --------------------------------------------|
| \_acme-challenge.example.org      | 60  | TXT  | FV5HgbpjIYe1x9MkPI81Nffo2oA-Jo2S88gCL7-Ky5P |
| \_acme-challenge.test.example.org | 60  | TXT  | WM5YIsgaZQv1b9DbRZ81EwCf2fi-Af2JlgxTC7-Up5D |

The TTL value can be set higher if wanted or necessary, I prefer to keep it as low as possible for this purpose. To make sure the verification is successful, it would be advised to run a script using DNS challenges in two parts, with a certain amount of time in between to allow for the DNS record to update. The user himself should make sure to set this DNS record before the record can be verified.
The DNS record name also depends on your provider, therefore getPendingAuthorizations() does not give you a ready-to-use record name. Some providers only accept a name like `_acme-challenge`, without the top domain name, for `_acme-challenge.example.org`. Some providers accept (require?) a full name like shown above.

*A wildcard domain, like `*.example.org`, will be verified as `example.org`, as shown above. This means the DNS record name should be `_acme-challenge.example.org`*

## Full example

For both HTTP and DNS authorizations, a full example is available in the project's main code directory. The HTTP authorization example is contained in one file. As described above, the DNS authorization example is split into two parts, to allow for the DNS record to update in the meantime. While the TTL of the record might be low, it can sometimes take some time for your provider to update your DNS records after an amendment.

If you can't get these examples, or the client library to work, try and have a look at the LetsEncrypt documentation mentioned above as well.

## Security

Security is an important subject regarding SSL/TLS certificates, of course. Since this client is a PHP script, it is likely this code is running on a web server. It is obvious that your private key, stored on your web server, should never be accessible from the web.
When the client created the keys directory for the first time, it will store a .htaccess file in this directory, denying all visitors. Always make sure yourself your keys aren't accessible from the web! I am in no way responsible if your private keys go public. If this does happen, the easiest solution is to change your account keys (described above) or deactivate your account and create a new one. Next, create a new certificate.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
