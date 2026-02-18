<?php

/**
 * This file is part of simple-web3-php package.
 *
 * (c) Alex Cabrera
 *
 * @author Alex Cabrera
 * @license MIT
 */

namespace iAmirNet\SWeb3;


use Elliptic\EC;
use kornrunner\Keccak;
use stdClass;
use Exception;





class Accounts
{

	public static function create()
	{
		//Generates an account object with private key and public key.

		// Create the keypair
		$privateKey = Keccak::hash(Utils::GetRandomHex(128), 256);

		return self::privateKeyToAccount($privateKey);
	}


	public static function privateKeyToAccount(string $privateKey, bool $ignoreLength = false)
	{
		//Generates an account object with private key and public key.

		if (substr($privateKey, 0, 2) == '0x') {
			$privateKey = substr($privateKey, 2, strlen($privateKey) - 2);
		}

		// 64 hex characters + hex-prefix
		if (!$ignoreLength && strlen($privateKey) !== 64) {
			throw new Exception("Private key must be 32 bytes long (" . (strlen($privateKey) / 2) . " provided)");
		}

		//get public key
		$ec = new EC('secp256k1');
		$ec_priv = $ec->keyFromPrivate($privateKey);
		$publicKey = $ec_priv->getPublic(true, "hex");

		// Returns a Web3 Account from a given privateKey
		$account = new Account();
		$account->privateKey = '0x' . $privateKey;
		$account->publicKey = '0x' . $publicKey;
		$account->address = self::ecKeyToAddress($ec_priv->pub);

		return $account;
	}


	public static function hashMessage(string $message) : string
	{
		if (substr($message, 0, 2) == '0x' && strlen($message) % 2 == 0 && ctype_xdigit(substr($message, 2))) {
			$message = hex2bin(substr($message, 2));
		}

		$messagelen = strlen($message);
		//"\x19Ethereum Signed Message:\n" + hash.length + hash and hashed using keccak256.
		$msg    = hex2bin("19") . "Ethereum Signed Message:" . hex2bin("0A") . $messagelen . $message;
		$hash   = Keccak::hash($msg, 256);

		return $hash;

		//https://github.com/web3/web3.js/blob/v1.2.11/packages/web3-eth-accounts/src/index.js (hashMessage)
		//web3.eth.accounts.hashMessage("Hello World")
 		//"0xa1de988600a42c4b4ab089b619297c17d53cffae5d5120d82d8a92d0bb3b78f2"
	}


	public static function ecKeyToAddress($pubEcKey) : string
	{
		return self::publicKeyToAddress($pubEcKey->encode("hex"));
	}


	public static function publicKeyToAddress(string $pubkey)
	{
		if (substr($pubkey, 0, 2) == '0x') $pubkey  = substr($pubkey, 2);
		return "0x" . substr(Keccak::hash(substr(hex2bin($pubkey), 1), 256), 24);
	}


	public static function signedMessageToAddress(string $message, string $signature) : string
	{
		$hash   = self::hashMessage($message);

		if (substr($signature, 0, 2) == '0x') {
			$signature = substr($signature, 2);
		}

		$sign   = ["r" => substr($signature, 0, 64), "s" => substr($signature, 64, 64)];
		$recid  = ord(hex2bin(substr($signature, 128, 2))) - 27;

		if ($recid != ($recid & 1))  {
			throw new Exception("Signature recovery not valid");
		}

		$ec = new EC('secp256k1');
		$pubEcKey = $ec->recoverPubKey($hash, $sign, $recid);

		return self::publicKeyToAddress($pubEcKey->encode("hex"));
	}


	public static function verifySignatureWithAddress(string $message, string $signature, string $address) : bool
	{
		$message_address = self::signedMessageToAddress($message, $signature);

		return $address == $message_address;
	}

}
