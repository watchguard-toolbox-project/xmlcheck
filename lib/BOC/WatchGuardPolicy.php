<?php
/**
 * Classfile for WatchGuardPolicy Object.
 *
 * @author       Werner Maier <wm@boc.de>
 * @copyright    (C) 2019 BOC IT-Security GmbH
 */

namespace BOC;

use SimpleXMLElement;

/**
 * Class WatchGuardPolicy
 * @package BOC
 */
class WatchGuardPolicy extends WatchGuardObject
{

    /**
     * stores all aliases from to: part
     * @var array
     */
    private $aliasesTo;
    /**
     * stores all aliases from from: part
     * @var array
     */
    private $aliasesFrom;

    /**
     * WatchGuardPolicy constructor.
     * @param SimpleXMLElement $element
     */
    public function __construct(SimpleXMLElement $element) {
        parent::__construct($element);
        $this->aliasesTo   = [];
        $this->aliasesFrom = [];
    }

    /**
     * returns an array of alias names, that are referenced in an simppleXMLElement list
     * like from: or to:
     * @param $list simpleXMLElement
     * @return array
     */
    private function getReferencedAliasesFromAliasList($list) {

        $retval = [];

        $aliasmemberlist = $list->{'alias'};
        foreach ($aliasmemberlist as $member) {
                $retval[] = $member->__toString();
        }

        return $retval;
    }

    /**
     * find referenced aliases in policy: look at from:, look at to:
     * @return array
     */
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

    /**
     * find referenced tags in policy
     * @return array
     */
    public function getReferencedTags() {

        $retval = [];

        print_r($this->obj->children());
        $fromaliaslist = $this->obj->children()->{'from-alias-list'};
        $this->aliasesFrom = $this->getReferencedAliasesFromAliasList($fromaliaslist);
        $retval = array_merge($retval, $this->aliasesFrom);

        $toaliaslist = $this->obj->children()->{'to-alias-list'};
        $this->aliasesTo = $this->getReferencedAliasesFromAliasList($toaliaslist);
        $retval = array_merge($retval, $this->aliasesTo);

        return $retval;
    }


    /**
     * stores the alias into the aliasesTo array.
     * @param $aliasarray
     */
    public function storeAliasesTo ($aliasarray) {
        $this->aliasesTo = array_merge($this->aliasesTo, $aliasarray);
    }

    /**
     * stores the alias into the aliasesFrom array.
     * @param $aliasarray
     */
    public function storeAliasesFrom ($aliasarray) {
        $this->aliasesFrom = array_merge($this->aliasesTo, $aliasarray);
    }

    /**
     * returns the name of the service of this policy
     * @return string
     */
    public function getService() {
        return $this->obj->service->__toString();
    }

    /**
     * detailed printout of policy information
     * @param WatchGuardXMLFile $xmlfile
     */
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

    /**
     * print this policy
     * @param WatchGuardXMLFile $xmlfile
     */
    public function textout($xmlfile) {
        global $options;

        print $this->obj->name->__toString() . "\n";

        if (isset($options["verbose"])) {
            $this->verbosetextout($xmlfile);
        }
    }

}

