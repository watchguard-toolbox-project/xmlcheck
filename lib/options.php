<?php

define(VERSION, "1.1");

$shortopts = "i:h";
$longopts = array(
    "infile:",
    "listaliases",
    "listpolicies",
    "help",
);
$options = getopt($shortopts, $longopts);

// show help
function displayHelpAndExit() {
    print "
    
    xmlcheck v" . VERSION . "
    
    Usage: 
    ./xmlcheck.php args|commands

    -h, --help              this help file
    -i, --infile filename   inputfile filename

    commands:
    --listaliases           lists all aliases
    --listpolicies          lists all policies
    \n";
    exit;
}

if (isset($options["help"]) || isset($options["h"]) || count($options) == 0) {
    displayHelpAndExit();
}
if (isset($options["infile"]) || isset($options["i"])) {
    $xmlfile = isset($options["i"]) ? $options["i"] : $options["infiles"];
    if (!is_file($xmlfile)) {
        print "error: file $xmlfile not found.\n";
        exit;
    }
}
if (!isset($xmlfile)) {
    print "error: no input file.\n";
    displayHelpAndExit();
}

