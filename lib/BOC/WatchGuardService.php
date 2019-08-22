<?php
/**
 * Classfile for WatchGuardService Object.
 *
 * @author       Werner Maier <wm@boc.de>
 * @copyright    (C) 2019 BOC IT-Security GmbH
 */
namespace BOC;

use SimpleXMLElement;

/**
 * Class WatchGuardService
 * @package BOC
 */
class WatchGuardService extends WatchGuardObject
{

    /**
     * WatchGuardService constructor.
     * @param SimpleXMLElement $element
     */
    public function __construct(SimpleXMLElement $element) {
        parent::__construct($element);
    }

    /**
     * Returns the property element of $this
     * @return string
     */
    public function getProperty() {
        $object = $this->obj;
        return $object->property->__toString();
    }

}

