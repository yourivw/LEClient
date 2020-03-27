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
	// Get the HTTP challenges from the pending authorizations.
	$pending = $order->getPendingAuthorizations(LEOrder::CHALLENGE_TYPE_HTTP);
	// Walk the list of pending authorization HTTP challenges.
	if(!empty($pending))
	{
		foreach($pending as $challenge)
		{
			// Define the folder in which to store the challenge. For the purpose of this example, a fictitious path is set.
			$folder = '/path/to/' . $challenge['identifier'] . '/.well-known/acme-challenge/';
			// Check if that directory yet exists. If not, create it.
			if(!file_exists($folder)) mkdir($folder, 0777, true);
			// Store the challenge file for this domain.
			file_put_contents($folder . $challenge['filename'], $challenge['content']);
			// Let LetsEncrypt verify this challenge.
			$order->verifyPendingOrderAuthorization($challenge['identifier'], LEOrder::CHALLENGE_TYPE_HTTP);
		}
	}
}
// Check once more whether all authorizations are valid before we can finalize the order.
if($order->allAuthorizationsValid())
{
	// Finalize the order first, if that is not yet done.
	if(!$order->isFinalized()) $order->finalizeOrder();
	// Check whether the order has been finalized before we can get the certificate. If finalized, get the certificate.
	if($order->isFinalized()) $order->getCertificate();
}
?>