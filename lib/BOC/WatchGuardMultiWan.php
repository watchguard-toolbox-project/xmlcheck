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
class WatchGuardMultiWan extends WatchGuardObject
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

    public function getAlgorithm(){
        return ($this->obj->{'algorithm'}->__toString());
    }
    public function getAlgorithmText(){
        switch ($this->obj->{'algorithm'}->__toString()) {
            case '0':       return 'none';
            case '1':       return 'round-robin';
            case '2':       return 'failover';
            case '3':       return '???=';
            case '4':       return 'interface overflow';
            case '5':       return 'routing table';
        };
    }

}
