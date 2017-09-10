# JWT
[![Build Status](https://travis-ci.org/revenuewire/jwt.svg?branch=master)](https://travis-ci.org/revenuewire/jwt)

### JWT Token
```php
require_once ("vendor/autoload.php");

$jwt = new \RW\JWT\Token();
$jwt->setIssuer('carambola')
    ->setAudience('jackfruit')
    ->setSecret("super-01-secret")
    ->setPayload(array("hello" => "world"))
    ->setExpiry(5);
$token = $jwt->getToken();
echo $token . "\n";
```

### JWT Validation
```php
$validator = \RW\JWT\Token::init($token);
$payload = $validator->setSecret("super-01-secret")
                ->validate()
                ->getPayload();
print_r($payload);
```