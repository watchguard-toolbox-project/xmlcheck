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
class WatchGuardDeviceConf extends WatchGuardObject
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

    public function getModel(){
        $tmp="";

        // agent can be array of agent-objects or single agent-object :(

        $tmp .= $this->obj->{'for-model'}->__toString();

        return ($tmp);
    }
    public function getSystemName(){
        $tmp="";

        // agent can be array of agent-objects or single agent-object :(

        $tmp .= $this->obj->{'system-name'}->__toString();

        return ($tmp);
    }

}
