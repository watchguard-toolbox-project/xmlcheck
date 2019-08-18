<?php

namespace BOC;

use SimpleXMLElement;

class WatchGuardService
{
    private $service;
    private $refcount;
    private $referencedBy = [];

    public function __construct(SimpleXMLElement $element) {
        $this->service = $element;
        $this->refcount = 0;
    }

    public function storeServiceReference($name,$type) {
        $this->referencedBy[$type][] = $name;
        $this->refcount++;
    }

    public function getProperty() {
        return $this->service->property->__toString();
    }

    private function verbosetextout($xmlfile) {

        if ($this->refcount > 0) {

            print"\n  References: \n";

            foreach ($this->referencedBy as $type => $references) {

                foreach ($references as $reference) {
                    printf ("    %-15s %-50s\n", $type, $reference);
                }
            }
            print "  Properrty: " . $this->getProperty() . "\n";
        }

        print "\n";
    }

    private function printName($xmlfile) {
        global $options;

        if ($this->refcount == 0) {
            print $this->service->name . " (unused)\n";
        } else {
            print $this->service->name . "\n";
        }

        if (isset($options["verbose"])) {
            $this->verbosetextout($xmlfile);
        }
    }

    public function textout($xmlfile) {

        global $options;

        if (($this->refcount == 0 && $this->getProperty() == "0")
            || isset($options['verbose'])){

            $this->printName($xmlfile);

        } else {

            if (!isset( $options["unused"] )) {
                $this->printName($xmlfile);
            }

        }

    }

}

