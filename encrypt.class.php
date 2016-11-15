<?php







class Encrypt
{
       public function __construct( )  {  }

       /////////////////// ONE WAY ENCRYPTION ///////////////////
       //-----------------MD5---------------//
       public function Encrypt_MD5($input){      return md5($input);  }
       public function Compare_MD5($input, $hash){      if(md5($input) === $hash){return 1;}return 0;}

       //-----------------MD4---------------//
       public function Encrypt_MD4($input){      return hash('md4', $input); }
       public function Compare_MD4($input, $hash){      if(hash('md4', $input) === $hash){return 1;}return 0;   }

       //-----------------MD2---------------//
       public function Encrypt_MD2($input){      return hash('md2', $input); }
       public function Compare_MD2($input, $hash){      if(hash('md2', $input) === $hash){return 1;}return 0;   }

       //-----------------SHA1---------------//
       public function Encrypt_SHA1($input){      return hash('sha1', $input);       }
       public function Compare_SHA1($input, $hash){      if(hash('sha1', $input) === $hash){return 1;}return 0;  }

       //-----------------sha256---------------//
       public function Encrypt_SHA256($input){      return hash('sha256', $input);     }
       public function Compare_SHA256($input, $hash){      if(hash('sha256', $input) === $hash){return 1;}return 0;       }

       //-----------------sha512---------------//
       public function Encrypt_SHA512($input){      return hash('sha512', $input);     }
       public function Compare_SHA512($input, $hash){      if(hash('sha512', $input) === $hash){return 1;}return 0;       }

       //-----------------Whirlpool---------------//
       public function Encrypt_Whirlpool($input){      return hash('Whirlpool', $input);  }
       public function Compare_Whirlpool($input, $hash){      if(hash('Whirlpool', $input) === $hash){return 1;}return 0;    }

       //-----------------crc32---------------//
       public function Encrypt_Crc32($input){      return hash('crc32', $input);  }
       public function Compare_Crc32($input, $hash){      if(hash('crc32', $input) === $hash){return 1;}return 0;       }

       //-----------------gost---------------//
       public function Encrypt_Gost($input){      return hash('gost', $input);  }
       public function Compare_Gost($input, $hash){      if(hash('gost', $input) === $hash){return 1;}return 0;       }

       //-----------------snefru---------------//
       public function Encrypt_Snefru($input){      return hash('snefru', $input);  }
       public function Compare_Snefru($input, $hash){      if(hash('snefru', $input) === $hash){return 1;}return 0;       }


       //-----------------BCRYPT---------------//
       public function Encrypt_BCrypt($input){      return password_hash($input, PASSWORD_BCRYPT);  }
       public function Compare_BCrypt($input, $hash){      if(password_verify (  $input ,  $hash )){return 1;}return 0;    }


       /////////////////// TWO WAY ENCRYPTION/DECRYPTION ///////////////////
       //----------------BASE64----------------//
       public function Encrypt_Base64($input){      return base64_encode($input);      }
       public function Compare_Base64($input, $hash){      if(base64_encode($input) === $hash){return 1;}return 0; }
       public function Decrypt_Base64($input){      return base64_decode ($input);     }

       //----------------Secure Encryptor----------------//
       function Encrypt_Secure($password, $data){$salt = substr(md5(mt_rand(), true), 8);$key = md5($password . $salt, true);$iv  = md5($key . $password . $salt, true);$ct = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv);return base64_encode('Salted__' . $salt . $ct);}
       function Decrypt_Secure($password, $data){$data = base64_decode($data); $salt = substr($data, 8, 8);$ct   = substr($data, 16);$key = md5($password . $salt, true);$iv  = md5($key . $password . $salt, true); $pt = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $ct, MCRYPT_MODE_CBC, $iv);return $pt;}

}















/*

@crypt($string)





hash('gost', $string)

hash('snefru', $string)*/













//
