<?php 

namespace Schluss\Tools;

include ('tools/encryption.php');

$password = 'aP@ssw@rd';
$data = 'encrypt me';


// ENCRYPTION:

// generate (iv/)salt for encrypting the url and additional data
$key_salt = Encryption::iv(16); // note this needs to be stored next to the encrypted data because it's needed for decryption
	
// generate derived key from given password
$key = Encryption::pbkdf2($password, $key_salt);

// generate salt for the encrypted data
$data_salt = Encryption::iv(16);
	
// encrypt the data
$encrypted_data = Encryption::encrypt($data, $key, $data_salt);
//echo $encrypted_data;

// what to store in db:
// $encrypted_data
// $key_salt


// DECRYPTION:

// (re)generate derived key from given password
$key = Encryption::pbkdf2($password, $key_salt);

// decrypt the data
$decrypted_data = Encryption::decrypt($encrypted_data, $key);

// tada, it's back:)
echo $decrypted_data;
