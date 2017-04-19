<?php
/**
 * Created by IntelliJ IDEA.
 * User: swang
 * Date: 2017-03-14
 * Time: 9:48 AM
 */

namespace RW\JWT;


class Validator
{
    private $claims64;
    private $headers64;
    private $signature;

    public $claims;
    public $headers;


    /**
     * Validator constructor.
     *
     * @param $token
     */
    function __construct($token)
    {
        $fields = explode('.', $token);
        if (count($fields) != 3) {
            throw new \InvalidArgumentException("Invalid Toke!");
        }
        list($this->headers64, $this->claims64, $this->signature) = $fields;
        $this->headers = json_decode(Utils::base64urlDecode($this->headers64), true);
        $this->claims = json_decode(Utils::base64urlDecode($this->claims64), true);
    }

    /**
     * Get Issuer
     *
     * @return null
     */
    public function getIssuer()
    {
        return !empty($this->claims['iss']) ? $this->claims['iss'] : null;
    }

    /**
     * Get Audience
     *
     * @return null
     */
    public function getAudience()
    {
        return !empty($this->claims['aud']) ? $this->claims['aud'] : null;
    }
    /**
     * Get Kid
     *
     * @return string/null
     */
    public function getKid()
    {
        return !empty($this->headers['kid']) ? $this->headers['kid'] : null;
    }

    /**
     * Check if Token is expired after verify if token is valid.
     *
     * @return bool
     */
    public function isTokenExpired()
    {
        if (!empty($this->claims['exp']) && $this->claims['exp'] > 0) {
            return ($this->claims['exp'] < time());
        }
        return false;
    }

    /**
     * Check if the token is valid.
     *
     * @param $alg
     * @param $secret
     *
     * @return bool
     */
    public function isValidToken($alg, $secret)
    {
        $token = implode('.', array($this->headers64, $this->claims64));
        $signature = Utils::base64urlEncode(hash_hmac($alg, $token, $secret, true));

        if ($this->signature !== $signature) {
            return false;
        }

        if ($this->isTokenExpired()) {
            return false;
        }

        //@todo: add more checks such as auds and issuers.

        return true;
    }

    /**
     * Get Payload
     * @warning: DO NOT USE THE PAYLOAD WITHOUT VALID TOKEN
     *
     * @return mixed
     */
    public function getPayload()
    {
        return $this->claims;
    }
}