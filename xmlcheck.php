#!/usr/bin/php
<?php
/**
 * xmlcheck.php - cli tool for checking watchguard xml configuration files
 *
 * commandline tool for checking watchguard xml configuration files
 * initial idea has been to check for unused aliases
 *
 */

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

if (isset($options["listaliases"])) {
    $policyxml->listAllAliases();
}

if (isset($options["listtags"])) {
    $policyxml->listAllTags();
}

if (isset($options["listpolicies"])) {
    $policyxml->listAllPolicies();
}

if (isset($options["listservices"])) {
    $policyxml->listAllServices();
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
