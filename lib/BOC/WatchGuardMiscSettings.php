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

    /**
     * Retrieves the MTU probing setting.
     *
     * @return string The MTU probing setting as a string.
     */
    public function getMTUProbing(){
        return ($this->obj->{'tcp-mtu-probing'}->__toString());
    }

    /**
     * Retrieves the auto-reboot enabled setting.
     *
     * @return string The auto-reboot setting as a string.
     */
    public function getAutoReboot(){
        return ($this->obj->{'auto-reboot'}->{'enabled'}->__toString());
    }

    /**
     * Retrieves the auto reboot time schedule.
     *
     * @return string The auto reboot time in the format "Day, at HH:MM", or an empty string if auto reboot is not enabled.
     */
    public function getAutoRebootTime(){
        $return = "";
        if ($this->getAutoReboot()=="1") {
            $day=$this->obj->{'auto-reboot'}->{'day'}->__toString();
            $hour=$this->obj->{'auto-reboot'}->{'hour'}->__toString();
            $minute=$this->obj->{'auto-reboot'}->{'minute'}->__toString();
            switch ($day) {
                case 7:     $day="Daily";
                            break;
                case 0:     $day="Sun";
                    break;
                case 1:     $day="Mon";
                    break;
                case 2:     $day="Tue";
                    break;
                case 3:     $day="Wed";
                    break;
                case 4:     $day="Thu";
                    break;
                case 5:     $day="Fri";
                    break;
                case 6:     $day="Sat";
                    break;
            }
            $return = sprintf("%s, at %02d:%02d",$day, $hour, $minute);
        }
        return $return;
    }

    /**
     * Retrieves the quality of service (QoS) setting.
     *
     * @return string The QoS setting as a string.
     */
    public function getQoS(){
        return ($this->obj->{'qos-enable'}->__toString());
    }

    /**
     * Retrieves the SYN checking setting.
     *
     * @return string The SYN checking setting as a string.
     */
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
