<?php

namespace BOC;

use SimpleXMLElement;

class WatchGuardService extends WatchGuardObject
{

    public function __construct(SimpleXMLElement $element) {
        parent::__construct($element);
    }

    public function getProperty() {
        $object = $this->obj;
        return $object->property->__toString();
    }

}

