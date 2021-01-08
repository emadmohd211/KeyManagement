<?php

include '../dbsettings.php';
include '../include/common.php';
include 'common/logging.php';


$log = new Logging();
$log->lfile('logs/get_key.log');

$keyID = $_REQUEST["privatekey"];
$isPrivateKey = true;
$isEncPrivateKey = false;

if ($keyID == "") {
    $keyID = $_REQUEST["publickey"];
    if ($keyID == "") {
        $keyID = $_REQUEST["encprivatekey"];
        if ($keyID != "") {
            $isEncPrivateKey = true;
            $isPrivateKey = false;
        }
    }
    else
        $isPrivateKey = false;
}

$log->lwrite("Request received from:" . $_SERVER["REMOTE_ADDR"] . " keyid:" . $keyID);

$returnString = "";
$num_id;
$result_id;


$link = mysql_connect($dbserver, $username, $password);
mysql_query("SET NAMES utf8;");
$retCode = @mysql_select_db($database);
if ($retCode == FALSE) {
    $log->lwrite(mysql_error());
    die("[POSTREPLY::FAIL - Internal Server Error]");
}

if ($keyID != "") {
    //$query_id = "SELECT OCTET_LENGTH(privatekey) len,privatekey key FROM keypair Where id = '$keyID'";
    if ($isPrivateKey) {
        $query_id = "SELECT OCTET_LENGTH(encrypt_keypair.privatekey) len, encrypt_keypair.privatekey 'key'";
        $query_id .= " FROM encrypt_keypair WHERE encrypt_keypair.id = '$keyID'";
    } else if ($isEncPrivateKey) {
        $query_id = "SELECT OCTET_LENGTH(encrypt_user_privatekey.privatekey) len, encrypt_user_privatekey.privatekey 'key'";
        $query_id .= " FROM encrypt_user_privatekey WHERE encrypt_user_privatekey.id = '$keyID'";
    } else {
        $query_id = "SELECT OCTET_LENGTH(encrypt_keypair.publickey) len, encrypt_keypair.publickey 'key'";
        $query_id .= " FROM encrypt_keypair WHERE encrypt_keypair.id = '$keyID'";
    }

    $result_id = mysql_query($query_id);
    if ($result_id == FALSE) {
    $log->lwrite(mysql_error());
    die("[POSTREPLY::FAIL - Internal Server Error]");
}

    $num_id = mysql_num_rows($result_id);

    if ($num_id == 0) {
        die ("[POSTREPLY::FAIL - Key not found]");
    }

    $userKey = mysql_result($result_id, 0, "key");
    $userKeyLen = mysql_result($result_id, 0, "len");

} else {
    echo "[POSTREPLY::FAIL - Key id is not sent]";
    return;
}
// close the database
mysql_close($link);
header('Content-type: text/plain');
header("Content-length: $userKeyLen");

//echo $userKey;

include ('phpseclib1.0.4/clientSoc.php');

echo base64_decode($decrypted_pri_key);



?>