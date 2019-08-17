<?php

namespace BOC;

use SimpleXMLElement;

class WatchGuardPolicy
{
    private $policy;

    public function __construct(SimpleXMLElement $element) {
        $this->policy = $element;
    }

    public function textout($xmlfile) {
        print $this->policy->name->__toString() . "\n";
    }

}

