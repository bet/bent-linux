#!/usr/bin/perl
# Replay a typescript created by the version of script
# provided with util-linux.
#
# Execute script like this (in bash):
#
#   script -f -t 2>times
#
# Do some full screen stuff. Read your mail, whatever.
# Exit from the script session and run replay.pl with the
# typescript and times files in the current directory.
# Don't you wish this was more portable?
#
# Copyright (c) 2004, Howard Owen.
# This script is free software. You can redistribute it
# and/or modify it under the same terms as Perl itself.
#
use strict;
use warnings;
use Time::HiRes qw( sleep );
use Fcntl qw( O_RDONLY );

my $typescript = "typescript";
my $timings="times";

my (@times,@counts);
open TI,$timings or die $!;
while (<TI>){
  chomp;
  ($times[$#times+1],$counts[$#counts+1])=split;
}
($times[$#times+1],$counts[$#counts+1])=(0,0);
sysopen TY,$typescript,O_RDONLY or die $!;
my $buff ="foo";
while ($buff ne "\n"){
   sysread TY,$buff,1; # Skip script(1) banner
}
syswrite STDOUT, "\n";
$counts[0]--;
for(my $c=0;$c<$#times;$c++){
  sysread TY,$buff,$counts[$c];
  syswrite STDOUT,$buff;
  sleep $times[$c+1];
}
print "\n";
