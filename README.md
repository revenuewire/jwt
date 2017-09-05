# JWT
[![Build Status](https://travis-ci.org/revenuewire/jwt.svg?branch=master)](https://travis-ci.org/revenuewire/jwt)

####JWT Token
```php
require_once ("vendor/autoload.php");

$jwt = new \RW\JWT\Token();
$jwt->setIssuer('carambola')
    ->setAudience('jackfruit')
    ->setPayload(array("hello" => "world"))
    ->setExpiry(5);
$token = $jwt->getToken("super-01-secret", null);
echo $token . "\n";
```

####JWT Validation
```php
$validator = \RW\JWT\Token::init($token, "super-01-secret");
$payload = $validator->getPayload();
print_r($payload);
```