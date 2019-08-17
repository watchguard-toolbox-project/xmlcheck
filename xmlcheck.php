#!/usr/bin/php
<?php

use BOC\WatchGuardXMLFile;

$xmlfile = ""; // will be delivered by options.php

/** @noinspection PhpIncludeInspection */
require_once(dirname(__FILE__) . '/vendor/autoload.php');

require_once("lib/functions.php");
require_once("lib/options.php");

// global variables from options.php:
// $options
// $xmlfile

$policyxml = new WatchGuardXMLFile($xmlfile);

if (isset($options["listaliases"])) {
    $policyxml->listAllAliases();
}

if (isset($options["listpolicies"])) {
    $policyxml->listAllPolicies();
}

if (isset($options["alias"]) || isset($options["a"])) {
    $printalias = isset($options["alias"]) ? $options["alias"] : $options["a"];
    $policyxml->printAlias($printalias);
}
