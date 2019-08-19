<?php

namespace BOC;

use SimpleXMLElement;

class WatchGuardPolicy extends WatchGuardObject
{

    private $aliasesTo;
    private $aliasesFrom;

    public function __construct(SimpleXMLElement $element) {
        parent::__construct($element);
    }

    private function getReferencedAliasesFromAliasList($list) {

        $retval = [];

        $aliasmemberlist = $list->{'alias'};
        print_r($aliasmemberlist);
        exit;
        foreach ($aliasmemberlist as $member) {
                $retval[] = $member->__toString();
        }

        return $retval;
    }

    public function getReferencedAliases() {

        $retval = [];

        $this->aliasesFrom = $this->getReferencedAliasesFromAliasList($this->obj->{'from-alias-list'});
        $retval = array_merge($retval, $this->aliasesFrom);

        $this->aliasesTo = $this->getReferencedAliasesFromAliasList($this->obj->{'to-alias-list'});
        $retval = array_merge($retval, $this->aliasesTo);

        return $retval;
    }

    public function getService() {
        return $this->obj->service->__toString();
    }

    protected function verbosetextout($xmlfile)
    {
        return;
        global $options;

        if (isset($options['verbose'])) {

            print_r($this->obj);
            print_r($this->aliasesTo);
            print_r($this->aliasesFrom);

            $fromAliases = implode(', ', $this->aliasesFrom);
            $toAliases   = implode(', ', $this->aliasesTo);

            print "  From   : " . $fromAliases . "\n";
            print "  To     : " . $toAliases . "\n";
            print "  Service: " . $this->getService() . "\n";
        }

        print "\n";
    }

    public function textout($xmlfile) {
        global $options;

        print $this->obj->name->__toString() . "\n";

        if (isset($options["verbose"])) {
            $this->verbosetextout($xmlfile);
        }
    }

}

