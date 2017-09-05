<?php
namespace RW\JWT;

use Aws\Kms\KmsClient;

class Token
{
    public $headers = array();
    public $claims = array();
    private $expiry;

    private $kmsConfig = [ "region" => "us-west-2", "version" => "2014-11-01", "alias" => "rw-jwt" ];
    private $context = ["type" => "JWT-KMS", "version" => "v1.0.0"];

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
     * @return Token
     */
    public static function init($token)
    {
        $fields = explode('.', $token);
        if (count($fields) != 3) {
            throw new \InvalidArgumentException("Invalid Toke!");
        }
        list($headers64, $claims64, $signature) = $fields;

        $headers = json_decode(self::base64urlDecode($headers64), true);

        if (self::isCacheExists("jwt." . $headers['kms']['key'])) {
            $secret = base64_decode(self::getCache("jwt." . $headers['kms']['key']));
        } else {
            $kmsClinet = new KmsClient([
                "region" => $headers['kms']['region'],
                "version" => $headers['kms']['version'],
            ]);
            $result = $kmsClinet->decrypt([
                'CiphertextBlob' => base64_decode($headers['kms']['key']),
                'EncryptionContext' => $headers['kms']['context']
            ]);
            $secret = $result->get('Plaintext');
            self::setCache("jwt." . $headers['kms']['key'], base64_encode($secret), 0);
        }

        $validationToken = implode('.', array($headers64, $claims64));
        if ($signature !== self::getSignature($validationToken, $secret)) {
            throw new \InvalidArgumentException("Invalid token");
        }

        $claims = json_decode(self::base64urlDecode($claims64), true);
        if (!empty($claims['exp']) && $claims['exp'] > 0 && $claims['exp'] < time()) {
            throw new \InvalidArgumentException("Token expired.");
        }

        /**
         * After this point, the token is validated and we can return the token object
         */
        $jwt = new Token();

        $jwt->claims = $claims;
        $jwt->headers = $headers;

        return $jwt;
    }

    /**
     * Set KMS configuration
     *
     * @param array $kms
     * @return $this
     */
    public function setKMS(array $kms)
    {
        $this->kmsConfig = array_merge_recursive($this->kmsConfig, $kms);
        return $this;
    }

    /**
     * Set Context
     * @param array $context
     * @return $this
     */
    public function setContext(array $context)
    {
        $this->context = array_merge_recursive($this->context, $context);
        return $this;
    }

    /**
     * get Context
     *
     * @return array
     */
    public function getContext()
    {
        return $this->context;
    }

    /**
     * Set # of seconds before the token considered expire
     * @param $seconds
     */
    public function setExpiry($seconds)
    {
        $this->expiry = $seconds;
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
     * Set KMS Header
     *
     * @param $key
     * @return $this
     */
    private function setKMSHeaders($key)
    {
        $this->headers['kms'] = [
            'region' => $this->kmsConfig['region'],
            'version' => $this->kmsConfig['version'],
            'alias' => $this->kmsConfig['alias'],
            'context' => $this->getContext(),
            'key' => $key
        ];
        return $this;
    }

    /**
     * Get Token
     * @param $cacheKey
     *
     * @return string
     */
    public function getToken($cacheKey = null)
    {
        if ($cacheKey !== null && self::isCacheExists($cacheKey . "-key") && self::isCacheExists($cacheKey. "-secret")) {
            $kmsKey = self::getCache($cacheKey . "-key");
            $secret = base64_decode(self::getCache($cacheKey . "-secret"));
        } else {
            $kmsClinet = new KmsClient([
                "region" => $this->kmsConfig['region'],
                "version" => $this->kmsConfig['version'],
            ]);
            $kmsData = ["KeyId" => "alias/" . $this->kmsConfig['alias'], "KeySpec" => "AES_256", "EncryptionContext" => $this->getContext()];
            $kmsResult = $kmsClinet->generateDataKey($kmsData);
            $kmsKey = base64_encode($kmsResult->get("CiphertextBlob"));
            $secret = $kmsResult->get('Plaintext');

            if ($cacheKey !== null) {
                self::setCache($cacheKey . "-key", $kmsKey);
                self::setCache($cacheKey . "-secret", base64_encode($secret));
            }
        }

        $this->setKMSHeaders($kmsKey);
        $this->setId(uniqid("JWT", true));
        $this->setIssueAt();
        if (!empty($this->expiry)) {
            $this->setExpirationTime(time() + $this->expiry);
        }

        $header = self::base64urlEncode(json_encode($this->headers));
        $payload = self::base64urlEncode(json_encode($this->claims));
        $token = $header . '.' . $payload;
        $signature = self::getSignature($token, $secret);

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
        return $this->claims;
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
        return self::base64urlEncode(hash_hmac("sha256", $token, $secret, true));
    }

    /**
     * Set Cache
     *
     * @param $k
     * @param $v
     */
    private static function setCache($k, $v, $ttl = 3600)
    {
        apcu_store($k, $v, 3600);
    }

    /**
     * Get Cache
     *
     * @param $k
     * @return mixed
     */
    private static function getCache($k)
    {
        return apcu_fetch($k);
    }

    /**
     * Is Cache Exists
     *
     * @param $k
     * @return bool|string[]
     */
    private static function isCacheExists($k)
    {
        return apcu_exists($k);
    }

    /**
     * To Encode a url
     *
     * @param $data
     * @return string
     */
    public static function base64urlEncode($data)
    {
        return str_replace('=', '', strtr(base64_encode($data), '+/', '-_'));
    }

    /**
     * To Decode a url
     *
     * @param $data
     * @return string
     */
    public static function base64urlDecode($data)
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $data .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($data, '-_', '+/'));
    }
}