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
class WatchGuardSSO extends WatchGuardObject
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
        parent::__construct($element);
    }

    public function debug(){
        print_r($this->obj);
    }
    public function isEnabled(){
        return ($this->obj->{'enabled'}->__toString());
    }
    public function getSSOAgents(){
        $tmp="";
        $lObject=json_decode(json_encode($this->obj));

        /*
        if ($this->isEnabled()==1) {
            foreach ($lObject->{'agent-list'}->{'agent'} as $agent) {
                print_r($agent->{'ip-addr'});
                $tmp.=",".$agent->{'ip-addr'};
            }
            $tmp=substr($tmp,1);
        }
        */

        error_reporting(E_ALL);
        if ($this->isEnabled()==1) {
            foreach ($this->obj->{'agent-list'}->{'agent'} as $agent) {
                if ($tmp!="") $tmp = $tmp . ",";
                $tmp .= $agent->{'ip-addr'}->__toString();
            }
        }

        return ($tmp);
    }

}
