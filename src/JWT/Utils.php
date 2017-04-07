<?php
/**
 * Created by IntelliJ IDEA.
 * User: swang
 * Date: 2017-03-14
 * Time: 9:24 AM
 */

namespace RW\JWT;

class Utils
{
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