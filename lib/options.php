<?php

define("VERSION", "0.1");

$shortopts = "i:ha:v";
$longopts = array(
    "infile:",
    "listaliases",
    "listpolicies",
    "alias:",
    "help",
    "verbose",
    "unused",
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
    -a aliasname, 
      --alias aliasname     print alias aliasname
    --listaliases           lists all aliases
    --listpolicies          lists all policies
    \n";
    exit;
}

if (isset($options["help"]) || isset($options["h"]) || count($options) == 0) {
    displayHelpAndExit();
}

if (isset($options["verbose"]) || isset($options["v"])) {
    $options["verbose"] = true;
}

if (isset($options["infile"]) || isset($options["i"])) {
    $xmlfile = isset($options["i"]) ? $options["i"] : $options["infile"];
    if (!is_file($xmlfile)) {
        print "error: file $xmlfile not found.\n";
        exit;
    }
}

if (!isset($xmlfile)) {
    print "error: no input file.\n";
    displayHelpAndExit();
}

