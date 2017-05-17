<?php

namespace Schluss\Tools;

/**
 * Encryption - PHP class for encryption / decryption using OpenSSL with included HMAC
 * @package Encryption
 * @author Schluss
 * @author Bob Hageman <bob@schluss.org>
 */
class Encryption
{

    /**
     * Generate initialization vector (iv)
     * @param int $length the lengt of the IV thats returned
     * @return iv
     */	
	public static function iv($length = 16)
	{
		return openssl_random_pseudo_bytes($length);
	}
	
    /**
     * Generate a PBKDF2 key derivation of a supplied password
	 * Wrapper of (hash_pbkdf2, http://php.net/manual/en/function.hash-pbkdf2.php)
     * @param string $password The password to use for the derivation.
     * @param string $salt The salt to use for the derivation. This value should be generated randomly.
     * @param string $algo Name of selected hashing algorithm
     * @param int $iterations The number of internal iterations to perform for the derivation.
     * @param int $length The length of the output string.
     * @param int $raw_outpu When set to TRUE, outputs raw binary data. FALSE outputs lowercase hexits.
     * @return derived key as lowercase hexits (or binary when raw_output = true)
     */		
	public static function pbkdf2($password, $salt, $algo = 'sha512', $iterations = 1000, $length = 20, $raw_output = false)
	{
		if(!in_array($algo, hash_algos(), true))
			exit($algo . ' not available');
	
		return hash_pbkdf2($algo, $password, $salt, $iterations, $length, $raw_output);
	}
	
    /**
     * Encrypt data
     * @param int $data data to be encrypted
     * @param int $key encryption key
     * @param int $iv initialization vector
     * @param int $algo encryption algorithm
     * @return encrypted data, combined with hmac: hmac.hmac_iv.encrypted(salt.data)
     */		
	public static function encrypt($data, $key, $iv, $algo = 'aes-256-ctr')
	{
		// encrypt data
		$data = $iv . openssl_encrypt($data, $algo, $key, OPENSSL_RAW_DATA, $iv);
		
		// generate hmac	
		$hmac_iv = Encryption::iv(64);
		$hmac_key = Encryption::pbkdf2($key, $hmac_iv);
		
		$hmac = hash_hmac('sha512', $data, $hmac_key, true);
		
		return $hmac.$hmac_iv.$data;
	}
	
    /**
     * Decrypt data
     * @param int $data data to be decrypted
     * @param int $key encryption key
     * @param int $algo encryption algorithm
     * @return decrypted data
     */		
	public static function decrypt($data, $key, $algo = 'aes-256-ctr')
	{
		// seperate hmac, hmac_iv and data
		$hmac = substr($data, 0 , 64); // length of $hmac during encryption
		$hmac_iv = substr($data, 64, 64); // get iv 
		$data = substr($data, 128);
		
		// regenerate hmac key
		$hmac_key = Encryption::pbkdf2($key, $hmac_iv);
		
		// calculate (new) hmac to compare to
		$hmac_compare = hash_hmac('sha512', $data, $hmac_key ,true);
		
		// time-attack-safe hmac comparison
		$diff = 0;
		for ($i = 0; $i < 64; $i++)
			$diff |= ord($hmac[$i]) ^ ord($hmac_compare[$i]);

		if ($diff !== 0)
			return false;
		
		// seperate the encypted data from the salt
		$iv = substr($data, 0, 16);
		$data = substr($data, 16);
		
		return openssl_decrypt($data, $algo, $key, OPENSSL_RAW_DATA, $iv);
	}
}
