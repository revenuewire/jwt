# jwt
JWT Token

~~~
require_once ("vendor/autoload.php");

$jwt = new \RW\JWT\Token("ad823js91&2s;", "sha256", 5, "hello");
$jwt->setIssuer('carambola')
    ->setAudience('jackfruit')
    ->setPayload(array("hello" => "world"));
$token = $jwt->getToken();
echo $token . "\n";

$validator = new \RW\JWT\Validator($token);

for($i = 0; $i < 10; $i++) {
    var_dump($validator->isValidToken("sha256", "ad823js91&2s;"));
    var_dump($validator->getPayload());
    sleep(1);
}
~~~