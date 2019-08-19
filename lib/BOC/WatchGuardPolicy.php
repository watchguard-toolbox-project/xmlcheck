<?php

namespace BOC;

use SimpleXMLElement;

class WatchGuardPolicy extends WatchGuardObject
{

    private $aliasesTo;
    private $aliasesFrom;

    public function __construct(SimpleXMLElement $element) {
        parent::__construct($element);
        $this->aliasesTo   = [];
        $this->aliasesFrom = [];
    }

    private function getReferencedAliasesFromAliasList($list) {

        $retval = [];

        $aliasmemberlist = $list->{'alias'};
        foreach ($aliasmemberlist as $member) {
                $retval[] = $member->__toString();
        }

        return $retval;
    }

    public function getReferencedAliases() {

        $retval = [];

        $fromaliaslist = $this->obj->children()->{'from-alias-list'};
        $this->aliasesFrom = $this->getReferencedAliasesFromAliasList($fromaliaslist);
        $retval = array_merge($retval, $this->aliasesFrom);

        $toaliaslist = $this->obj->children()->{'to-alias-list'};
        $this->aliasesTo = $this->getReferencedAliasesFromAliasList($toaliaslist);
        $retval = array_merge($retval, $this->aliasesTo);

        return $retval;
    }

    public function storeAliasesTo ($aliasarray) {
        $this->aliasesTo = array_merge($this->aliasesTo, $aliasarray);
    }

    public function storeAliasesFrom ($aliasarray) {
        $this->aliasesFrom = array_merge($this->aliasesTo, $aliasarray);
    }

    public function getService() {
        return $this->obj->service->__toString();
    }

    protected function verbosetextout($xmlfile)
    {
        global $options;

        if (isset($options['verbose'])) {

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

