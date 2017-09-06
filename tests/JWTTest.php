<?php
class JWTTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @return string
     */
    public function testToken()
    {
        $jwt = new \RW\JWT\Token();
        $jwt->setIssuer('carambola')
            ->setAudience('jackfruit')
            ->setPayload(array("hello" => "world"))
            ->setSecret("super-01-secret")
            ->setExpiry(5);
        $token = $jwt->getToken(null);
        $this->assertNotEmpty($token);

        return $token;
    }

    /**
     * @depends testToken
     * @param $token
     */
    public function testValidation($token)
    {
        $validator = \RW\JWT\Token::init($token)->validate("super-01-secret");
        $payload = $validator->getPayload();

        $this->assertSame($payload['hello'], "world");
        $this->assertSame($validator->getIssuer(), "carambola");
        $this->assertSame($validator->getAudience(), "jackfruit");
    }

    /**
     * @depends testToken
     * @param $token
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage Token verification failed
     */
    public function testValidationFailed($token)
    {
        $validator = \RW\JWT\Token::init($token)->validate("super-02-secret")->getPayload();
    }

    /**
     * @depends testToken
     * @param $token
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage Token expired
     */
    public function testTokenExpired($token)
    {
        sleep(6);
        $validator = \RW\JWT\Token::init($token)->validate("super-01-secret")->getPayload();
    }
}