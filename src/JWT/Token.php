<?php
namespace RW\JWT;

use Aws\Kms\KmsClient;
use RW\JWT\Helpers\Base64Url;

class Token
{
    public $headers = array();

    private $claims = array();
    private $expiry;
    private $secret = null;
    private $token = null;
    private $isValidated = false;

    /**
     * JWT constructor.
     */
    function __construct()
    {
        $this->headers = array(
            'typ' => 'JWT',
            'alg' => 'HS256',
        );

        return $this;
    }

    /**
     * Init token
     *
     * @param $token
     *
     * @return Token
     */
    public static function init($token)
    {
        $fields = explode('.', $token);
        if (count($fields) != 3) {
            throw new \InvalidArgumentException("Invalid Toke");
        }
        list($headers64, $claims64, $signature) = $fields;

        $headers = json_decode(Base64Url::decode($headers64), true);
        $claims = json_decode(Base64Url::decode($claims64), true);

        $jwt = new Token();
        $jwt->token = $token;
        $jwt->headers = $headers;
        $jwt->claims = $claims;

        return $jwt;
    }

    /**
     * Validate token
     *
     * @return $this
     */
    public function validate()
    {
        $fields = explode('.', $this->token);
        if (count($fields) != 3) {
            throw new \InvalidArgumentException("Invalid Toke");
        }
        list($headers64, $claims64, $signature) = $fields;

        $validationToken = implode('.', array($headers64, $claims64));
        if ($signature !== self::getSignature($validationToken, $this->getSecret())) {
            throw new \InvalidArgumentException("Token verification failed");
        }

        $claims = json_decode(Base64Url::decode($claims64), true);
        if (!empty($claims['exp']) && $claims['exp'] > 0 && $claims['exp'] < time()) {
            throw new \InvalidArgumentException("Token expired");
        }

        $this->isValidated = true;
        return $this;
    }

    /**
     * Set # of seconds before the token considered expire
     * @param $seconds
     *
     * @return $this
     */
    public function setExpiry($seconds)
    {
        $this->expiry = $seconds;
        return $this;
    }

    /**
     * Set Secret
     * @param $secret
     *
     * @return $this
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;
        return $this;
    }

    /**
     * Get Secret
     * @return string
     */
    public function getSecret()
    {
        return $this->secret;
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
        return $this;
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

        $header = Base64Url::encode(json_encode($this->headers));
        $payload = Base64Url::encode(json_encode($this->claims));
        $token = $header . '.' . $payload;
        $signature = self::getSignature($token, $this->getSecret());

        return $token . '.' . $signature;
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
     * Get Payload
     *
     * @return mixed
     */
    public function getPayload()
    {
        if ($this->isValidated) {
            return $this->claims;
        }

        throw new \InvalidArgumentException("Cannot access payload without validation.");
    }

    /**
     * @return null
     */
    public function getKid()
    {
        return !empty($this->headers['kid']) ? $this->headers['kid'] : null;
    }

    /**
     * @param null $kid
     * @return $this
     */
    public function setKid($kid)
    {
        $this->headers['kid'] = $kid;
        return $this;
    }

    /**
     * Get the Signature
     *
     * @param $token
     * @param $secret
     *
     * @return string
     */
    private static function getSignature($token, $secret)
    {
        return Base64Url::encode(hash_hmac("sha256", $token, $secret, true));
    }

    /**
     * @return string
     */
    public function getAlg()
    {
        return !empty($this->headers['alg']) ? $this->headers['alg'] : null;
    }

    /**
     * @param string $alg
     * @return Token
     */
    public function setAlg($alg)
    {
        $this->headers['alg'] = $alg;
        return $this;
    }

}