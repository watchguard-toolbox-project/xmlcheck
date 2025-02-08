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
     * stores all tags
     * @var array
     */
    private $tags;

    /**
     * stores firewall action Allow/Block/Reject
     * @var string
     */
    public $firewallAction;

    /**
     * WatchGuardPolicy constructor.
     * @param SimpleXMLElement $element
     */
    public function __construct(SimpleXMLElement $element) {
        parent::__construct($element);
        $this->aliasesTo   = [];
        $this->aliasesFrom = [];
        $this->tags        = [];
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

        $retval = array_merge($retval, $this->getReferencedAliasesTo());
        $retval = array_merge($retval, $this->getReferencedAliasesFrom());

        /*
        $tmp=  [];
        # $this->allAliases[$alias->name->__toString()] = new WatchGuardAlias($alias);
        foreach ($retval as $member) {
            $tmp[] = array_merge($tmp, $this->allAliases[$member]);
        }
        array_merge($retval, $tmp);
        */

        return $retval;
    }

    /**
     * find referenced aliasesTo in policy: look at from:, look at to:
     * @return array
     */
    public function getReferencedAliasesTo() {

        $retval = [];

        $toaliaslist = $this->obj->children()->{'to-alias-list'};
        $this->aliasesTo = $this->getReferencedAliasesFromAliasList($toaliaslist);
        $retval = array_merge($retval, $this->aliasesTo);

        return $retval;
    }

    /**
     * find referenced aliasesFrom in policy: look at from:, look at to:
     * @return array
     */
    public function getReferencedAliasesFrom() {

        $retval = [];

        $fromaliaslist = $this->obj->children()->{'from-alias-list'};
        $this->aliasesFrom = $this->getReferencedAliasesFromAliasList($fromaliaslist);
        $retval = array_merge($retval, $this->aliasesFrom);

        return $retval;
    }

    /**
     * find referenced tags in policy
     * @return array
     */
    public function getReferencedTags() {

        $retval = [];
        // TODO => fromAliasList seems wrong here.
        // TODO => toAliasList seems wrong here.

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
     * stores the tags into the tags array.
     * @param $tags
     */
    public function storeTag ($tag) {
        $tagsarray= array($tag);
        $this->tags = array_merge($this->tags, $tagsarray);
    }
    /**
     * retrieves the tags into the tags array.
     * @return array
     */
    public function getTags()
    {
        $tags = $this->tags;
        return $tags;
    }


    /**
     * stores the alias into the aliasesFrom array.
     * @param $aliasarray
     */
    public function storeAliasesFrom ($aliasarray) {
        $this->aliasesFrom = array_merge($this->aliasesTo, $aliasarray);
    }

    /**
     * retrieves the alias into the aliasesTo array.
     * @return array
     */
    public function getAliasesTo()
    {
        $to = $this->aliasesTo;
        if (is_array($to) && isset($to[0])) {
            if (preg_match("/\.1\.(to|from)/", $to[0])) {
                // remove pseudo-alias policy-name.1.to; policy-name.1.to
                array_shift($to);
            }
        }
        return $to;
    }

    /**
     * retrieves the alias into the aliasesFrom array.
     * @return array
     */
    public function getAliasesFrom()
    {
        $from = $this->aliasesFrom;
        if (is_array($from) && isset($from[0])) {
            if (preg_match("/\.1\.(to|from)/", $from[0])) {
                // ressolve $from [0]
                print_r($from[0]);
                // remove pseudo-alias policy-name.1.to; policy-name.1.from
                array_shift($from);
            }
        }
        return $from;
    }

    /**
     * returns the name of the service of this policy
     * @return string
     */
    public function getService() {
        return $this->obj->service->__toString();
    }
    public function getType() {
        return $this->getService();
    }

    /**
     * @return string Allow|Deny
     */
    public function getAction() {
        switch($this->obj->firewall->__toString()) {
            case "1":
                $ret = "Allow";
                break;
            case "2":
                $ret = "Deny";
                break;
            case "4":
                $ret = "Proxy";
                break;
            default:
                $ret = "???" . $this->obj->firewall->__toString() . "???";
                break;
        }
        return $ret;
    }

    public function getDescriptionPretty() {
        // Policy added on 2016-11-17T16:41:07+01:00.
        static $month = [
            "Jan" => "01",
            "Feb" => "02",
            "Mar" => "03",
            "Apr" => "04",
            "May" => "05",
            "Jun" => "06",
            "Jul" => "07",
            "Aug" => "08",
            "Sep" => "09",
            "Oct" => "10",
            "Nov" => "11",
            "Dec" => "12",
        ];

        $desc = $this->getDescription();
        if (preg_match("/Policy added on (\d\d\d\d-\d\d-\d\d)T\d\d:\d\d:\d\d[-+]\d\d:\d\d\./", $desc, $matches)) {
            $desc="Created: ".$matches[1];
        };
        if (preg_match("/Policy added on (Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ".
                              "(\d\d) \d\d:\d\d:\d\d [A-Z]{3,4} (\d\d\d\d)\./", $desc, $matches)) {{}
            if (isset($month[$matches[2]])) {
                $desc="Created: ".$matches[4]."-".$month[$matches[2]]."-".$matches[3];
            } else {
                $desc="Created: ".$matches[4]."-".$matches[2]."-".$matches[3];
            }
        };

        if ($desc == "") {
            switch ($this->getNamePretty()) {
                case "Any From Firebox":
                    $desc="Built-in policy to allow outgoing traffic";
                    break;
                case "Allow-IKE-to-Firebox":
                    $desc="Built-in policy to allow incoming IKE";
                    break;
                case "WatchGuard":
                case "WatchGuard Web UI":
                    $desc="Built-in policy to allow Firebox management";
                    break;
                case "Unhandled Internal Packet":
                case "Unhandled External Packet":
                    $desc="Built-in policy to deny all pakets - final drop";
                    break;
            }
        }

        return $desc;
    }

    /**
     * returns the enable/disable state of this policy
     * @return bool
     */
    public function isEnabled() {

        $result = false;

        if ($this->obj->enable == 1) {
            $result = true;
        }

        return $result;
    }

    /**
     * detailed printout of policy information
     * @param WatchGuardXMLFile $xmlfile
     */
    protected function verbosetextout($xmlfile)
    {
        global $options;

        if (isset($options['verbose'])) {

            $fromAliases = implode(', ', $this->getAliasesFrom());
            $toAliases   = implode(', ', $this->getAliasesTo());
            $tags        = implode(', ', $this->getTags());

            print "  From   : " . $fromAliases . "\n";
            print "  To     : " . $toAliases . "\n";
            print "  Service: " . $this->getService() . "\n";
            print "  Enabled: " . ($this->isEnabled() === true ? "yes" : "no") . "\n";
            print "  Action : " . $this->getAction() . "\n";
            print "  Tags   : " . $tags . "\n";
            print "  Comment: " . $this->getDescriptionPretty() . "\n";
        }

        print "\n";
    }

    /**
     * print this policy
     * @param WatchGuardXMLFile $xmlfile
     */
    public function textout($xmlfile) {
        global $options;

        print preg_replace("/ /", ".", $this->obj->name->__toString()) . "\n";

        if (isset($options["verbose"])) {
            $this->verbosetextout($xmlfile);
        }
    }

    /**
     * @return string
     */
    public function getFirewallAction()
    {
        return $this->firewallAction;
    }

    /**
     * @param string $firewallAction
     */
    public function setFirewallAction($firewallAction)
    {
        $this->firewallAction = $firewallAction;
    }

}

