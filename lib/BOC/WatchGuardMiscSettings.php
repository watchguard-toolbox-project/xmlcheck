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
class WatchGuardMiscSettings extends WatchGuardObject
{
    /**
     * color of Tag
     * @var string
     */
    protected $color;

    /**
     * WatchGuardTag constructor.
     * @param SimpleXMLElement $xmlfile
     */
    public function __construct(SimpleXMLElement $xmlfile)
    {
        parent::__construct($xmlfile->{'system-parameters'}->{'misc-global-setting'});
    }

    public function getAutoOrder(){
        return ($this->obj->{'auto-order-enabled'}->__toString());
    }

    public function getMTUProbing(){
        return ($this->obj->{'tcp-mtu-probing'}->__toString());
    }

    public function getAutoReboot(){
        return ($this->obj->{'auto-reboot'}->{'enabled'}->__toString());
    }

    public function getQoS(){
        return ($this->obj->{'qos-enable'}->__toString());
    }
    public function getSynChecking(){
        return ($this->obj->{'syn-checking-enable'}->__toString());
    }
    public function getVlanForward(){
        return ($this->obj->{'vlan-forward'}->__toString());
    }

    public function getBlockSpoofEnabled(){
        return ($this->obj->{'block-spoof-enabled'}->__toString());
    }
    public function getAutoBlockedDuration(){
        return ($this->obj->{'auto-blocked-duration'}->__toString());
    }
}
