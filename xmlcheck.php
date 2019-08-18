#!/usr/bin/php
<?php

use BOC\WatchGuardXMLFile;

$xmlfile = ""; // will be delivered by options.php

/** @noinspection PhpIncludeInspection */
require_once(dirname(__FILE__) . '/vendor/autoload.php');

require_once("lib/functions.php");

$options = [];
require_once("lib/options.php");

// global variables from options.php:
// $options
// $xmlfile

$policyxml = new WatchGuardXMLFile($xmlfile);

if (isset($options["simplexmlout"])) {
    print_r($policyxml);
    exit;
}

if (isset($options["listaliases"])|| isset($options["l"])) {
    $policyxml->listAllAliases();
}

if (isset($options["listpolicies"]) || isset($options["p"])) {
    $policyxml->listAllPolicies();
}

if (isset($options["alias"]) || isset($options["a"])) {
    $printalias = isset($options["alias"]) ? $options["alias"] : $options["a"];
    if (is_array($printalias)) {
        $printaliases = $printalias;
    } else {
        $printaliases = [];
        $printaliases[] = $printalias;
    }
    foreach ($printaliases as $printalias) {
        print "\n";
        $policyxml->printAlias($printalias);
        print "\n";
    }
}
