<?php
/**
 * Created by IntelliJ IDEA.
 * User: swang
 * Date: 2017-09-09
 * Time: 6:12 PM
 */

namespace RW\JWT\Helpers;


class Cache
{
    /**
     * Set Cache
     *
     * @param $k
     * @param $v
     *
     * @return array|bool
     */
    public static function setCache($k, $v)
    {
        $val = var_export($v, true);
        // HHVM fails at __set_state, so just use object cast for now
        $val = str_replace('stdClass::__set_state', '(object)', $val);
        // Write to temp file first to ensure atomicity
        $tmp = "/tmp/$k." . uniqid('', true) . '.tmp';
        file_put_contents($tmp, '<?php $val = ' . $val . ';', LOCK_EX);
        rename($tmp, "/tmp/$k");
    }

    /**
     * Get Cache
     *
     * @param $k
     * @return mixed
     */
    public static function getCache($k)
    {
        @include "/tmp/$k";
        return isset($val) ? $val : false;
    }
}