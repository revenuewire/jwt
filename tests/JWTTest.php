<?php
class JWTTest extends \PHPUnit\Framework\TestCase
{
    /**
     * Set up
     */
    public static function setUpBeforeClass()
    {

    }

    public static function tearDownAfterClass()
    {

    }

    /**
     * @return string
     */
    public function testToken()
    {
        $jwt = new \RW\JWT\Token();
        $jwt->setIssuer('carambola')
            ->setAudience('jackfruit')
            ->setPayload(array("hello" => "world"))
            ->setExpiry(5);
        $token = $jwt->getToken("super-01-secret", null);
        $this->assertNotEmpty($token);

        return $token;
    }

    /**
     * @depends testToken
     * @param $token
     */
    public function testValidation($token)
    {
        $validator = \RW\JWT\Token::init($token, "super-01-secret");
        $payload = $validator->getPayload();
        $this->assertSame($payload['hello'], "world");
    }

    /**
     * @depends testToken
     * @param $token
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage Invalid token
     */
    public function testValidationFailed($token)
    {
        $validator = \RW\JWT\Token::init($token, "super-02-secret");
    }

    /**
     * @depends testToken
     * @param $token
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage Token expired.
     */
    public function testTokenExpired($token)
    {
        sleep(6);
        $validator = \RW\JWT\Token::init($token, "super-01-secret");
    }
}