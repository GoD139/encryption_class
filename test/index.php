<html>
<head>

</head>
<body>


       <?php

       include_once('../encrypt.class.php');
       $Crypt = New Encrypt();

       $MethodName = array("MD5","MD4","MD2","SHA1","SHA256","SHA512","Whirlpool","Crc32","Gost","Snefru","BCrypt"); //array of hashing names as they are written in the class

       $String = "Some text here"; // String being hashed
       $CompareString = "Some text here"; // string compared to hash (1 = same, 0 = not same)

       foreach($MethodName as $MName)
       {
              $HashString = call_user_func(array($Crypt, 'Encrypt_'.$MName), $String);
              $HashCompare = call_user_func(array($Crypt, 'Compare_'.$MName), $CompareString, $HashString);

              echo "<h4>".$MName ."</h4>";
              echo "<b>Plain string:</b> ". $String ."<br />";
              echo "<b>Hashed string:</b> ". $HashString  ."<br />";
              echo "<b>Compare string and hash:</b> ". $HashCompare  ."<br />";
              echo "<br /><br /><br />";
       }



       /*
       How you'd most likely write it in your own code

       $Crypt->Encrypt_MD5("Some text here");
       $Crypt->Compare_MD5("Text you want to compare","Hashed string here");

       */


       ?>











</body>
</html>
