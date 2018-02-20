<?php
namespace RW\JWT\Helpers;

use Aws\Kms\KmsClient;

class KMS
{
    public $region;
    public $version;
    public $alias;

    private $ciphertextBlob;
    private $plaintext;
    private $keyRotation = 3600;
    private $cacheKey = "kms-oS7I426LX2";

    function __construct($alias = "rw-jwt", $region = "us-west-2", $version = "2014-11-01")
    {
        $this->alias = $alias;
        $this->region = $region;
        $this->version = $version;
    }

    /**
     * Decrypt a kid
     *
     * @param $kid
     * @return mixed|null
     */
    public static function decrypt($kid)
    {
        list($region, $version, $base64EncodedCiphertextBlob) = explode('.', $kid);
        $kmsClinet = new KmsClient([
            "region" => $region,
            "version" => $version,
        ]);
        $result = $kmsClinet->decrypt([
            'CiphertextBlob' => Base64Url::decode($base64EncodedCiphertextBlob),
        ]);
        $secret = $result->get('Plaintext');
        return $secret;
    }

    /**
     * Get The Kid
     *
     * @return string
     */
    public function getKid()
    {
        return implode('.', [$this->region, $this->version, Base64Url::encode($this->getCiphertextBlob())]);
    }

    /**
     * Generate Data key
     */
    public function generateDataKey()
    {
        if (($kmsResult = Cache::getCache($this->getCacheKey())) !== false) {
            $kmsResult = unserialize(Cache::getCache($this->getCacheKey()));
        } else {
            $kmsClinet = new KmsClient([
                "region" => $this->getRegion(),
                "version" => $this->getVersion(),
            ]);
            $kmsData = [
                "KeyId" => "alias/" . $this->getAlias(),
                "KeySpec" => "AES_256",
            ];
            $kmsResult = $kmsClinet->generateDataKey($kmsData);
            Cache::setCache($this->getCacheKey(), serialize($kmsResult));
        }

        $this->setCiphertextBlob($kmsResult->get("CiphertextBlob"));
        $this->setPlaintext($kmsResult->get('Plaintext'));

        return $this;
    }

    /**
     * @return string
     */
    public function getRegion()
    {
        return $this->region;
    }

    /**
     * @param string $region
     * @return KMS
     */
    public function setRegion($region)
    {
        $this->region = $region;
        return $this;
    }

    /**
     * @return string
     */
    public function getVersion()
    {
        return $this->version;
    }

    /**
     * @param string $version
     * @return KMS
     */
    public function setVersion($version)
    {
        $this->version = $version;
        return $this;
    }

    /**
     * @return string
     */
    public function getAlias()
    {
        return $this->alias;
    }

    /**
     * @param string $alias
     * @return KMS
     */
    public function setAlias($alias)
    {
        $this->alias = $alias;
        return $this;
    }

    /**
     * @return mixed
     */
    public function getCiphertextBlob()
    {
        return $this->ciphertextBlob;
    }

    /**
     * @param mixed $ciphertextBlob
     * @return KMS
     */
    public function setCiphertextBlob($ciphertextBlob)
    {
        $this->ciphertextBlob = $ciphertextBlob;
        return $this;
    }

    /**
     * @return mixed
     */
    public function getPlaintext()
    {
        return $this->plaintext;
    }

    /**
     * @param mixed $plaintext
     * @return KMS
     */
    public function setPlaintext($plaintext)
    {
        $this->plaintext = $plaintext;
        return $this;
    }

    /**
     * Set Cache Key
     * @param $key
     * @return $this
     */
    public function setCacheKey($key)
    {
        $exceptList = ['-', '_'];
        $validationKey = str_replace($exceptList, "", $key);
        if (empty($validationKey) || !ctype_alnum($validationKey)) {
            throw new \InvalidArgumentException("Invalid cache key.");
        }
        //only [a-zA-z0-9-_] allowed
        $this->cacheKey = $key;

        return $this;
    }

    /**
     * Get Cache Key
     * @return null
     */
    public function getCacheKey()
    {
        if (!empty($this->keyRotation)) {
            return $this->cacheKey . '-' .intval(time()/$this->keyRotation);
        }
        return $this->cacheKey;
    }

    /**
     * @return int
     */
    public function getKeyRotation()
    {
        return $this->keyRotation;
    }

    /**
     * @param int $ttl
     * @return KMS
     */
    public function setKeyRotation($ttl)
    {
        if (!is_numeric($ttl) || $ttl < 0) {
            throw new \InvalidArgumentException("cache ttl must be a positive integer.");
        }
        $this->keyRotation = $ttl;
        return $this;
    }
}