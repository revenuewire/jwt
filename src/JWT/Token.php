<?php
namespace RW\JWT;

class Token
{
    public static $algs = array(
        'sha256' => array('f' => 'hash_hmac', 't' => 'HS256'),
    );

    public $headers = array();
    public $claims = array();
    private $secret;
    private $expiry;
    private $kid;
    private $alg;

    /**
     * JWT constructor.
     *
     * @param $secret
     * @param string $alg
     * @param null $expiry
     * @param string $kid
     */
    function __construct($secret, $alg = 'sha256', $expiry = null, $kid = "")
    {
        $this->headers = array(
            'typ' => 'JWT',
        );

        if (!empty($kid)) {
            $this->headers['kid'] = $kid;
            $this->kid = $kid;
        }

        if (empty(self::$algs[$alg])) {
            throw new \InvalidArgumentException("Algorithm is not supported!");
        }
        $this->alg = $alg;
        $this->headers['alg'] = self::$algs[$alg]['t'];

        if (!empty($expiry)) {
            $this->expiry = $expiry;
        }

        if (strlen($secret) < 8) {
            throw new \InvalidArgumentException("Secret too short!");
        }

        if (!preg_match("#[0-9]+#", $secret)) {
            throw new \InvalidArgumentException("Secret must include at least one number!");
        }

        if (!preg_match("#[a-zA-Z]+#", $secret)) {
            throw new \InvalidArgumentException("Secret must include at least one letter!");
        }

        $this->secret = $secret;

        return $this;
    }

    /**
     * Set Payload data
     *
     * @param $payload
     *
     * @return $this
     */
    public function setPayload(array $payload)
    {
        $this->claims = array_merge($this->claims, $payload);
        return $this;
    }

    /**
     * Set Type
     *
     * The "typ" (type) Header Parameter defined by [JWS] and [JWE] is used
     * by JWT applications to declare the media type [IANA.MediaTypes] of
     * this complete JWT.  This is intended for use by the JWT application
     * when values that are not JWTs could also be present in an application
     * data structure that can contain a JWT object; the application can use
     * this value to disambiguate among the different kinds of objects that
     * might be present.  It will typically not be used by applications when
     * it is already known that the object is a JWT.  This parameter is
     * ignored by JWT implementations; any processing of this parameter is
     * performed by the JWT application.  If present, it is RECOMMENDED that
     * its value be "JWT" to indicate that this object is a JWT.  While
     * media type names are not case sensitive, it is RECOMMENDED that "JWT"
     * always be spelled using uppercase characters for compatibility with
     * legacy implementations.  Use of this Header Parameter is OPTIONAL.
     *
     * @param $type
     *
     * @return $this
     */
    public function setType($type)
    {
        $this->headers['typ'] = $type;
        return $this;
    }

    /**
     * Set Issuer
     *
     * The "iss" (issuer) claim identifies the principal that issued the
     * JWT.  The processing of this claim is generally application specific.
     * The "iss" value is a case-sensitive string containing a StringOrURI
     * value.  Use of this claim is OPTIONAL.
     *
     * @param $issuer
     *
     * @return $this
     */
    public function setIssuer($issuer)
    {
        $this->claims['iss'] = $issuer;
        return $this;
    }

    /**
     * Set Audience
     *
     * The "aud" (audience) claim identifies the recipients that the JWT is
     * intended for.  Each principal intended to process the JWT MUST
     * identify itself with a value in the audience claim.  If the principal
     * processing the claim does not identify itself with a value in the
     * "aud" claim when this claim is present, then the JWT MUST be
     * rejected.  In the general case, the "aud" value is an array of case-sensitive
     * strings, each containing a StringOrURI value.  In the special case when
     * the JWT has one audience, the "aud" value MAY be a single case-sensitive string
     * containing a StringOrURI value.  The interpretation of audience values is generally
     * application specific. Use of this claim is OPTIONAL.
     *
     * @param $audience
     *
     * @return $this
     */
    public function setAudience($audience)
    {
        $this->claims['aud'] = $audience;
        return $this;
    }

    /**
     * Expiration Time
     *
     * The "exp" (expiration time) claim identifies the expiration time on
     * or after which the JWT MUST NOT be accepted for processing.  The
     * processing of the "exp" claim requires that the current date/time
     * MUST be before the expiration date/time listed in the "exp" claim.
     *
     * @param $expirationTime
     *
     * @return $this
     */
    protected function setExpirationTime($expirationTime)
    {
        $this->claims['exp'] = $expirationTime;
        return $this;
    }

    /**
     * (JWT ID) Claim
     *
     * The "jti" (JWT ID) claim provides a unique identifier for the JWT.
     * The identifier value MUST be assigned in a manner that ensures that
     * there is a negligible probability that the same value will be
     * accidentally assigned to a different data object; if the application
     * uses multiple issuers, collisions MUST be prevented among values
     * produced by different issuers as well.  The "jti" claim can be used
     * to prevent the JWT from being replayed.  The "jti" value is a case-
     * sensitive string.  Use of this claim is OPTIONAL.

     * @param $id
     *
     * @return $this
     */
    public function setId($id)
    {
        $this->claims['jti'] = $id;
        return $this;
    }

    /**
     * Set Issue At
     *
     * The "iat" (issued at) claim identifies the time at which the JWT was
     * issued.  This claim can be used to determine the age of the JWT.  Its
     * value MUST be a number containing a NumericDate value.  Use of this
     * claim is OPTIONAL.
     */
    public function setIssueAt()
    {
        $this->claims['iat'] = time();
    }

    /**
     * Get Token
     *
     * @return string
     */
    public function getToken()
    {
        $this->setId(uniqid("JWT", true));
        $this->setIssueAt();
        if (!empty($this->expiry)) {
            $this->setExpirationTime(time() + $this->expiry);
        }

        $header = Utils::base64urlEncode(json_encode($this->headers));
        $payload = Utils::base64urlEncode(json_encode($this->claims));
        $token = $header . '.' . $payload;
        $signature = $this->getSignature($token);

        return $token . '.' . $signature;
    }

    /**
     * Get the Signature
     *
     * @param $token
     *
     * @return string
     */
    private function getSignature($token)
    {
        return Utils::base64urlEncode(hash_hmac($this->alg, $token, $this->secret, true));
    }


    /**
     * Check if the token is valid
     *
     * @param $token
     *
     * @return bool
     */
//    public function isValidToken($token)
//    {
//        $fields = explode('.', $token);
//        if (count($fields) != 3) {
//            return false;
//        }
//        list($headers, $claims, $signature) = $fields;
//
//        $token = $headers . '.' . $claims;
//
//        return ($signature == $this->getSignature($token) && !$this->isTokenExpired());
//    }

    /**
     * Check if Token expired.
     *
     * @return bool
     */
//    public function isTokenExpired()
//    {
//        return (!empty($this->claims['exp']) && $this->claims['exp'] < time());
//    }
}