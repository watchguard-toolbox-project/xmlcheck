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
class WatchGuardSSLVPN extends WatchGuardObject
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
    public function __construct(SimpleXMLElement $xmlfile)
    {
        parent::__construct($xmlfile->{'sslvpn-list'}->{'sslvpn'});
    }

    public function isEnabled(){
        return ($this->obj->{'enable'}->__toString());
    }
    public function isAutoRecoonect(){
        return ($this->obj->{'auto-reconnect'}->__toString());
    }
    public function renegDataChannel(){
        return ($this->obj->{'gateway'}->{'reneg-datachannel'}->__toString());
    }
}
