<?php
namespace RW\JWT\Helpers;

class Base64Url
{
    /**
     * To Encode a url
     *
     * @param $data
     * @return string
     */
    public static function encode($data)
    {
        return str_replace('=', '', strtr(base64_encode($data), '+/', '-_'));
    }

    /**
     * To Decode a url
     *
     * @param $data
     * @return string
     */
    public static function decode($data)
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $data .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($data, '-_', '+/'));
    }

}