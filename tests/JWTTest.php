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
        $token = $jwt->getToken();
        $this->assertNotEmpty($token);

        return $token;
    }

    /**
     * Test KMS
     * @return string
     */
    public function testKMSToken()
    {
        $kms = new \RW\JWT\Helpers\KMS();
        $kms->setRegion("us-west-1")
            ->generateDataKey();

        $jwt = new \RW\JWT\Token();
        $jwt->setIssuer('carambola')
            ->setAudience('jackfruit')
            ->setKid($kms->getKid())
            ->setSecret($kms->getPlaintext())
            ->setPayload(array("hello" => "kms"))
            ->setExpiry(5);
        $token = $jwt->getToken();
        $this->assertNotEmpty($token);

        return $token;
    }

    /**
     * @depends testKMSToken
     * @param $token
     */
    public function testValidationKMS($token)
    {
        $jwt = \RW\JWT\Token::init($token);
        $jwt->setSecret(\RW\JWT\Helpers\KMS::decrypt($jwt->getKid()))
            ->validate();

        $payload = $jwt->getPayload();

        $this->assertSame($payload['hello'], "kms");
        $this->assertSame($jwt->getIssuer(), "carambola");
        $this->assertSame($jwt->getAudience(), "jackfruit");
    }

    /**
     * @depends testToken
     * @param $token
     */
    public function testValidation($token)
    {
        $validator = \RW\JWT\Token::init($token)
                        ->setSecret("super-01-secret")
                        ->validate();
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
        $validator = \RW\JWT\Token::init($token)
                        ->setSecret("super-02-secret")
                        ->validate()
                        ->getPayload();
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
        $validator = \RW\JWT\Token::init($token)
                        ->setSecret("super-01-secret")
                        ->validate()
                        ->getPayload();
    }
}