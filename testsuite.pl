#!/bin/perl
use strict;
use warnings;
use Data::Dumper;
use Net::Interface;
 use Getopt::Long;
use POSIX qw(ceil);

#use bignum;
my $nodes;
my @addr;
my @nodepid;
my @nodeout;
my @childs;
my $sleep = 10;

my $kill;
my $spawn;
my $max;
my $verbose;
  GetOptions ("nodes=i" => \$nodes,    # numeric
              "kill=i"   => \$kill,      # numeric
              "max=i"   => \$max,      # numeric
              "spawn=i"   => \$spawn,      # numeric
              "verbose"  => \$verbose)   # flag
  or die("Error in command line arguments\n");
if(!defined $nodes) {
    $nodes = 3;
}
chomp(my $lo = `ip -o link show | awk '/^([0-9]+):\\s([a-zA-Z0-9]+).+loopback.+\$/{print \$2}' | tr -d ':'`);
if($lo eq "") {
    print "No Loopback Interface found\n";
    exit(1);
}
my $end = 0;
$SIG{INT}  = sub { $end++ };

print "Start with $nodes nodes on interface $lo";
for(my $i = 0;$i<$nodes && $end == 0;$i++) {
    my $hex = sprintf("%X", $i+1);
    my $rnd_master = $childs[rand @childs]{addr};
    $childs[$i]{addr} = "::$hex";
    if($verbose) {
        print "ifconfig $lo inet6 add $childs[$i]{addr}\n";
    }
    system("ifconfig $lo inet6 add $childs[$i]{addr} > /dev/null 2>&1");
    $childs[$i]{master_addr} = $rnd_master;
    $childs[$i]{killed}  = undef;
    $childs[$i]{cmd} = "";
    if($i == 0) {
            $childs[$i]{cmd} = "./example master $childs[$i]{addr}";
    } else {
            $childs[$i]{cmd} = "./example slave $childs[$i]{addr} $rnd_master";
    }
    if($verbose) {
              print "$childs[$i]{cmd}\n";
    }
    $childs[$i]{pid}  = fork();
    $childs[$i]{outname} = "./log/chord.$childs[$i]{pid}.log";
    if(not $childs[$i]{pid}) {
        exec($childs[$i]{cmd});
        exit(0);
    }
    sleep(1);
}
#if(defined($kill) && $kill > 0) {
#    my $kill_count = ceil((@childs/100)*$kill);
#    print "Kill is defined. Start to kill $kill% random nodes $kill_count/@childs\n";
#    for(my $i = 0;$i<$kill_count;$i++) {
#        my $victim = rand(@childs);
#        $childs[$victim]{killed} = 1;
#        if($verbose) {
#            print "Kill $childs[$victim]{cmd} with pid  $childs[$victim]{pid}\n";
#        }
#        system("kill $childs[$victim]{pid}");
#        splice(@childs,$victim,1);
#    }
#}
my $ret = 0;
my $c = 0;
my @sorted;
while($end == 0) {
    sleep 1;
    if($end > 0){
        last;
    }
    for(my $i = 0;$i<@childs;$i++) {
        my $pid = $childs[$i]{pid};
        my $fname = $childs[$i]{outname};
        if (-e $fname) {
          chomp(my $last = `tail -1 $fname`);
          $childs[$i]{laststate} = $last;
          (my $pre, my $me, my $suc) = split(/\|/, $childs[$i]{laststate});
          if(defined($me)) {
            $childs[$i]{me} = $me + 0;
            if($pre ne "NULL") {
              $childs[$i]{state}{$me}{pre} = $pre + 0;
            } else {
                $childs[$i]{state}{$me}{pre} = $pre;
            }
            if($suc ne "NULL") {
              $childs[$i]{state}{$me}{suc} = $suc + 0;
            } else {
                $childs[$i]{state}{$me}{suc} = $suc;
            }
          } else {
               $childs[$i]{me} = undef;
          }
        } else {
          $childs[$i]{state} = undef;
        }
    }
    @sorted =  sort { (defined($a->{me}) <=> defined($b->{me})) || $a->{me} <=> $b->{me} } @childs; 
    my $not_in_sync = 0;
    for(my $i = 0;$i<@childs;$i++) {
        my $me = $sorted[$i]{me};
        for(my $e = 0;$e<@childs;$e++) {
            if($i != $e) {
                if(defined($me) && defined($sorted[$e]{me}) && $me == $sorted[$e]{me}) {
                    print "Collision found $i ($me) == $e ($sorted[$e]{me})\n";
                    $end = 1;
                }
            }
        }
        if($end > 0) {
            last;
        }
        print "Check $me suc: $sorted[$i]{state}{$me}{suc} pre: $sorted[$i]{state}{$me}{pre}\n";
        if(defined($me)) {
            if(@childs == 1) {
                if($sorted[$i]{state}{$me}{pre} eq "NULL" || $sorted[$i]{state}{$me}{suc} eq "NULL") {
                    print "@childs == 1 && $sorted[$i]{state}{$me}{pre} eq 'NULL' || $sorted[$i]{state}{$me}{suc} eq 'NULL'";
                    $not_in_sync++;
                    next;
                }
                if(!($me == $sorted[$i]{state}{$me}{pre} && $me == $sorted[$i]{state}{$me}{suc})) {
                    print "@childs == 1 && $me == $sorted[$i]{state}{$me}{pre} && $me == $sorted[$i]{state}{$me}{suc}";
                    $not_in_sync++;
                }
                next;
            }
            if($sorted[$i]{state}{$me}{pre} eq "NULL" || $sorted[$i]{state}{$me}{pre} eq "NULL") {
                print "$sorted[$i]{state}{$me}{pre} eq 'NULL' || $sorted[$i]{state}{$me}{pre} eq 'NULL'\n";
                $not_in_sync++;
                next;
            }
            if($i == 0) {
                if(!($sorted[$i]{state}{$me}{pre} == $sorted[-1]{me} && $sorted[$i]{state}{$me}{suc} == $sorted[$i+1]{me})) {
                    print "Error 1 $sorted[$i]{state}{$me}{pre} == $sorted[-1]{me} && $sorted[$i]{state}{$me}{suc} == $sorted[$i+1]{me}\n";
                    $not_in_sync++;
                }
            } elsif($i == @childs-1) {
                if(!($sorted[$i]{state}{$me}{pre} == $sorted[$i-1]{me} && $sorted[$i]{state}{$me}{suc} == $sorted[0]{me})) {
                    print "Error 2 $sorted[$i]{state}{$me}{pre} == $sorted[$i-1]{me} && $sorted[$i]{state}{$me}{suc} == $sorted[0]{me}\n";
                    $not_in_sync++;
                }
            } else {
                if(!($sorted[$i]{state}{$me}{pre} == $sorted[$i-1]{me} && $sorted[$i]{state}{$me}{suc} == $sorted[$i+1]{me})) {
                    print "Error 3 $sorted[$i]{state}{$me}{pre} == $sorted[$i-1]{me} && $sorted[$i]{state}{$me}{suc} == $sorted[$i+1]{me}\n";
                    $not_in_sync++;
                }
            }
        } else {
            $not_in_sync++;
        }
    }
    $c++;
    if($verbose) {
        print Dumper(@sorted);
        if(defined($max)) {
            print "Run $c/$max sync: $not_in_sync end: $end\n";
        }
        else {
            print "Run $c sync: $not_in_sync end: $end\n";
        }
    }
    if(defined($max) && $c == $max) {
        $ret = $not_in_sync;
        last
    }
    if($not_in_sync == 0 || $end > 0){
        if(!defined($kill)) {
            print "Ring in sync\n";
            last;
        } else {
             print "Ring in sync\n";
             if(@childs == 1) {
                 last;
             }
        }
    } else {
        print "Not in sync yet\n";
    }
    if(defined($kill) && ($c % $kill) == 0 && @childs > 1) {
        my $victim = rand(@childs);
        $childs[$victim]{killed} = 1;
        print "Kill $childs[$victim]{cmd} with pid  $childs[$victim]{pid}\n";
        system("kill $childs[$victim]{pid}");
        splice(@childs,$victim,1);
    }
}

print "Kill\n";
my $count = 0;
for(my $i = 0;$i<@childs;$i++) {
    if(defined($childs[$i])) {
        print "Kill: $childs[$i]{pid}\n";
        system("kill $childs[$i]{pid}");
    }
}
exit($ret);