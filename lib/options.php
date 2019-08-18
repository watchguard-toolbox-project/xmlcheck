<?php

define("VERSION", "0.2");

$shortopts = "i:ha:vlp";
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
function displayHelp() {
    print "
    
    xmlcheck v" . VERSION . "
    
    Usage: 
    ./xmlcheck.php args|commands

    -h, --help              this help file
    -i, --infile filename   inputfile filename

    commands:
    -a aliasname, 
      --alias aliasname     print alias aliasname
    -l, --listaliases       lists all aliases
    -p, --listpolicies      lists all policies
    \n";
}
function displayHelpAndExit() {
    displayHelp();
    exit;
}
function displayHelpAndError($error) {
    displayHelp();
    print "\nerror: $error\n\n";
}

if (isset($options["help"]) || isset($options["h"]) || count($options) == 0) {
    displayHelpAndExit();
}

if (isset($options["verbose"]) || isset($options["v"])) {
    $options["verbose"] = true;
}

$xmlfile = "";
if (isset($options["infile"]) || isset($options["i"])) {
    $xmlfile = isset($options["i"]) ? $options["i"] : $options["infile"];
    if (is_array($xmlfile)) {
        displayHelpAndError("-i accepts only ONE file argument.");
        print "hint: problem might be with this option: '" . $xmlfile[1] .
              "'.\n      is it a valid option/action/argument?\n\n";
        exit;
    }
    if (!is_file($xmlfile)) {
        displayHelpAndError("file '$xmlfile' not found.");
        exit;
    }
}

if ($xmlfile === "") {
    displayHelpAndError("no input file.");
    exit;
}

