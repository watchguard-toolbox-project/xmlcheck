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

if (isset($options["listnats"])) {
    $policyxml->listAllNats();
}

if (isset($options["listtags"])) {
    $policyxml->listAllTags();
}

if (isset($options["listpolicies"])) {
    if (isset($filtertag) && is_array($filtertag)) {
        $policyxml->setPolicyTagFilter($filtertag);
    }
    if (isset($filtertype) && is_array($filtertype)) {
        $policyxml->setPolicyTypeFilter($filtertype);
    }
    if (isset($filterexcludetype) && is_array($filterexcludetype)) {
        $policyxml->setPolicyExcludeTypeFilter($filterexcludetype);
    }
    if (isset($filterfrom) && is_array($filterfrom)) {
        $policyxml->setPolicyFromFilter($filterfrom);
    }
    if (isset($filterto) && is_array($filterto)) {
        $policyxml->setPolicyToFilter($filterto);
    }
    if (isset($filteraction)) {
        $policyxml->setPolicyActionFilter($filteraction);
    }
    $policyxml->listAllPolicies();
}

if (isset($options["listservices"])) {
    if (isset($filtertype) && is_array($filtertype)) {
        $policyxml->setPolicyTypeFilter($filtertype);
    }
    if (isset($filterport) && is_array($filterport)) {
        $policyxml->setTypePortFilter($filterport);
    }
    if (isset($filterexcludetype) && is_array($filterexcludetype)) {
        $policyxml->setPolicyExcludeTypeFilter($filterexcludetype);
    }
    $policyxml->listAllServices();
}

if (isset($options["listtunnels"])) {
    $policyxml->listAllTunnels();
}

if (isset($options["alias"]) || isset($options["a"])) {
    foreach ($printaliases as $printalias) {
        print "\n";
        $policyxml->printAlias($printalias);
        print "\n";
    }
}

if (isset($options["info"])) {
    $format='text';
    if (isset($options['json'])) {
        $format = 'json';
    }
    if (isset($options['json-pretty'])) {
        $format = 'json-pretty';
    }
$policyxml->printInfo($format);
}

if (isset($options['fwcheck'])) {
    $policyxml->printInfo('prepare');

    $flags = null;
    if (isset($options['json-pretty'])) {
        $flags= JSON_PRETTY_PRINT;
    }
    print (json_encode($policyxml->getOutput(), $flags));
}

if (isset($options["warnings"])) {
    $policyxml->printWarnings();
}
