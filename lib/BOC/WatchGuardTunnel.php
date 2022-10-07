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
class WatchGuardTunnel extends WatchGuardObject
{
    /**
     * type of Alias: address, alias, group, etc.
     * @var string
     */
    protected $tunnels;

    /**
     * WatchGuardAlias constructor.
     * @param SimpleXMLElement $element
     */
    public function __construct(SimpleXMLElement $element)
    {
        parent::__construct($element);
        $this->tunnels=[];
    }

    public function addTunnelRoute($pair) {
        /*
         * TODO: calculate directions
        $direction = $pair->{'direction'}->value->{'0'}->__toString();
        var_dump($pair->{'direction'});
        if ($direction == "bi-directional") $direction = "<==>";
        */
        $direction="<==>";
        $this->tunnels[] = array(
            "obj" => $pair,
            "local" => $pair->{'local-addr'}->value->__toString(),
            "remote" => $pair->{'remote-addr'}->value->__toString(),
            "direction" => $direction,
        );
    }

    /**
     * verbose output of alias contents.
     * overloads base class method
     * @param WatchGuardXMLFile $xmlfile
     */
    protected function verbosetextout($xmlfile) {

        // parent::verbosetextout($xmlfile);
        $description = $this->obj->description->__toString();
        if ($description == "Created by Policy Manager") $description = "manual";
        if (preg_match("/DVCP IKE Policy for Gateway/", $description)) $description = "managed";
        printf("    Type  : %s\n", $description);
        foreach ($this->tunnels as $tunnel) {
            printf("    Tunnel: %s %s %s\n", $tunnel['local'], $tunnel['direction'], $tunnel['remote']);
        }

        print "\n";

    }

    /**
     * output for alias objects, suppressing some defaults
     * overloads base class method
     *
     * @param WatchGuardXMLFile $xmlfile
     */
    public function textout($xmlfile)
    {

        global $options;

        parent::textout($xmlfile);
    }

    /**
     * print the name of $this
     * @param $xmlfile WatchGuardXMLFile in which other objects can be found
     */
    protected function printName($xmlfile) {
        global $options;

        /*
         *
         */
        if ($this->obj->enabled->__toString() == "1") {
            print $this->obj->name->__toString() . "\n";
        } else {
            print $this->obj->name->__toString() . " (disabled)\n";
        }

        if (isset($options["verbose"])) {
            $this->verbosetextout($xmlfile);
        }
    }

}

