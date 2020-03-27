<?php
// Sets the maximum execution time to two minutes, to be sure.
ini_set('max_execution_time', 120);
// Including the autoloader.
include __DIR__.'/../vendor/autoload.php';

// Importing the classes.
use LEClient\LEClient;
use LEClient\LEOrder;

// Listing the contact information in case a new account has to be created.
$email = array('info@example.org');
// Defining the base name for this order
$basename = 'example.org';
// Listing the domains to be included on the certificate
$domains = array('example.org', 'test.example.org');

// Initiating the client instance. In this case using the staging server (argument 2) and outputting all status and debug information (argument 3).
$client = new LEClient($email, LEClient::LE_STAGING, LECLient::LOG_STATUS);
// Initiating the order instance. The keys and certificate will be stored in /example.org/ (argument 1) and the domains in the array (argument 2) will be on the certificate.
$order = $client->getOrCreateOrder($basename, $domains);
// Check whether there are any authorizations pending. If that is the case, try to verify the pending authorizations.
if(!$order->allAuthorizationsValid())
{
	// Get the DNS challenges from the pending authorizations.
	$pending = $order->getPendingAuthorizations(LEOrder::CHALLENGE_TYPE_DNS);
	// Walk the list of pending authorization DNS challenges.
	if(!empty($pending))
	{
		foreach($pending as $challenge)
		{
			// For the purpose of this example, a fictitious functions creates or updates the ACME challenge DNS record for this domain. 
			setDNSRecord($challenge['identifier'], $challenge['DNSDigest']);
		}
	}
}
?>