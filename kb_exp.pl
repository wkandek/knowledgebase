#
# kb_exp.pl - parses the textual KB info prints QID w/ exploits
#
# v1.0a
#
#
# v1.0a - wkandek - initial version 

## Modules
use strict;
no strict 'subs';
use XML::Twig;           # XML manipulation library
use Getopt::Long;        # parses the option passed to the program

# use Data::Dumper;

##
my $DEBUG = 1;
my $INFO = 2;

## Variables
my $help;                                         # for help option
my $debug;                                        # for debug option
my $verbose;                                      # for verbose option

my $scriptname = "kb";                            # defines scriptname used for log
my $version = "v1.0a";                            # defines version
my $verboselogfilename = $scriptname.".log";      # logfile to use
my $logidnumber = int( rand( 100000 ));           # log ID number - helps in correlating loglines

my %qids;                                         # associative array to store qids
my %categories;                                   # associative array to store categories
my %types;                                        # associative array to store types
my %patchable;                                    # associative array to store whether patchable
my %vref;                                         # associative array to store whether patchable
my %titles;
my %severities;
my %cveids;
my %vrefs;
my %exploitationqids;

my $linecounter;
my $now;

my $key;


### Subroutines

## ----------------------------------------------------------------------
## usage
## prints short usage message if param --help is given to the program
##
## @param arg1 - NONE
## ----------------------------------------------------------------------
sub usage() {
  print "Usage: $scriptname [OPTIONS]\n$version\n";
  print "--help - this message\n";
  print "--verbose - log to logfile\n--debug - log more information to logfile\n";
  return( 1 );
}


## ----------------------------------------------------------------------
## printlog
## prints log messages to a file, depending on verbose setting on cmdline
## understands DEBUG and prints more info if DEBUG is set
##
## @param arg1 - level of logging verbosity
## @param arg2..x - logmessage(s)
## ----------------------------------------------------------------------
sub printlog( @ ) {
  my $level = shift( @_ );


  if (( $level == $DEBUG )) {
    if ( $debug ) {
      open( LOGFILE, ">>$verboselogfilename" ) || die "$scriptname: Logfile $verboselogfilename coul
d not be opened\n";
      print LOGFILE localtime( time()).":$scriptname:$logidnumber:$level:@_\n";
      close( LOGFILE )
    }
  }
  else {
    if ( $verbose ) {
      open( LOGFILE, ">>$verboselogfilename" ) || die "$scriptname: Logfile $verboselogfilename coul
d not be opened\n";
      print LOGFILE localtime( time()).":$scriptname:$logidnumber:$level:@_\n";
      close( LOGFILE )
    }
  }
}


## ----------------------------------------------------------------------
## kbextract
## populates the internal kb structure from the XML twig
##
## @param arg1 - root
## @param arg2 - twig
## ----------------------------------------------------------------------
sub kbextract
{
  my( $twig, $kb)= @_;
  my $qid;
  my $type;
  my $severity;
  my $title;
  my $category;
  my $patch;
  my $pdate;
  my $vr;
  my $vrid;
  my @vrs;
  my @correlationtypes;
  my $ctype;
  my @esources;
  my $src;


  $qid = $kb->first_child("QID")->text;
  $type = $kb->first_child("VULN_TYPE")->text;
  $severity = $kb->first_child("SEVERITY_LEVEL")->text;
  $title = $kb->first_child("TITLE")->text;
  $category = $kb->first_child("CATEGORY")->text;
  $patch = $kb->first_child("PATCHABLE")->text;

  # is there an exploit
  if ( $kb->first_child("CORRELATION")) {
    @correlationtypes = $kb->first_child("CORRELATION")->children;
    foreach $ctype (@correlationtypes) {
      if ( $ctype->first_child("EXPLT_SRC")) {
        $exploitationqids{$linecounter}++;
        printlog $DEBUG, "Exploit: ".$qid;
      }
    }
  }

  # is there a Vendor IDE
  if ( $kb->first_child("VENDOR_REFERENCE_LIST")) {
    @vrs = $kb->first_child("VENDOR_REFERENCE_LIST")->children;
    foreach $vr (@vrs) {
      $vrid = $vr->first_child("ID")->text;
      printlog $DEBUG, $vrid." ".$qid;
    }
  }

  $qids{$linecounter} = $qid;
  $categories{$linecounter} = $category;
  $types{$linecounter} = substr($type,0,1);
  $severities{$linecounter} = $severity;
  $titles{$linecounter} = $title;
  $patchable{$linecounter} = $patch;
  $vref{$linecounter} = $vrid;
  $linecounter++;

  $twig->purge;                             # delete the twig so far
}


## ----------------------------------------------------------------------
## parse_kb_file
## parses the KB file and populates internal structures via XML twig
##
## @param arg1 - NONE
## ----------------------------------------------------------------------
sub parse_kb_file() {

  # create the twig
  printlog $INFO, "enter new";
  my $twig= new XML::Twig( twig_handlers => { VULN => \&kbextract } );

  # parse the twig
  $twig->parsefile( "kb.xml") || die "$scriptname: kb.xml file could no be opened";
}



## main
GetOptions( "verbose"=>\$verbose,
            "debug"=>\$debug,
            "help"=>\$help );
$verbose && print "Start run: $version ".localtime(time())."\n";
printlog $INFO, "Start run $verbose $debug $help";

$help && usage() && exit;

$verbose && print "Parameters:  \n";
printlog $INFO, "Parameters:  ";


$linecounter = 0;
parse_kb_file();

foreach my $key ( keys %qids ) {
  if ( $exploitationqids{$key} ) {
    print $qids{$key}."\n";
  }
}

printlog $INFO, "End run";

