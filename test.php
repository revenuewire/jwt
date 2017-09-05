<?php
/**
 * Created by IntelliJ IDEA.
 * User: swang
 * Date: 2017-03-13
 * Time: 1:36 PM
 */
require_once ("vendor/autoload.php");

$jwt = new \RW\JWT\Token();
$jwt->setIssuer('carambola')
    ->setAudience('jackfruit')
    ->setPayload(array("hello" => "world"))
    ->setExpiry(5);

$token = $jwt->getToken("my-jwt-2");
echo $token . "\n";

for($i = 0; $i < 10; $i++) {
    $validator = \RW\JWT\Token::init($token);
    var_dump($validator->getPayload());
    sleep(1);
}