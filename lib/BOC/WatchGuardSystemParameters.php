<?php
/**
 * Alias object class.
 *
 * @author Werner Maier (wm@boc.de)
 * @copyright 2019 BOC IT-Security GmbH
 */
namespace BOC;

use SimpleXMLElement;

/**
 * Class WatchGuardAlias
 * @package BOC
 */
class WatchGuardSystemParameters extends WatchGuardObject
{
    /**
     * color of Tag
     * @var string
     */
    protected $color;

    /**
     * WatchGuardTag constructor.
     * @param SimpleXMLElement $element
     */
    public function __construct(SimpleXMLElement $element)
    {
        parent::__construct($element->{'system-parameters'});
    }

    /**
     * Determines if the feature key auto-sync is enabled.
     *
     * @return string Returns "1" if the feature key auto-sync is enabled, otherwise "0".
     */
    public function featureKeyAutoSyncIsEnabled()
    {
        $return = "0";
        if ($this->obj->{'lsd'}->{'feature-key-auto-sync'}->__toString() == "1")
        {
            $return = "1";
        }
        return $return;
    }

    /**
     * Determines whether the WatchGuard Cloud feature is enabled.
     *
     * @return string Returns "1" if the WatchGuard Cloud feature is enabled, otherwise returns "0".
     */
    public function isWatchGuardCloudEnabled()
    {
        $return = "0";
        if ($this->obj->{'daas-client'}->{'enabled'}->__toString() == "1")
        {
            $return = "1";
        }
        return $return;
    }

}
