#!/bin/perl
use strict;
use warnings;
use Data::Dumper;
use Net::Interface;
use Getopt::Long;
use POSIX qw(ceil);
use Scalar::Util qw(looks_like_number);
use IO::Select;

#use bignum;
my $nodes;
my @addr;
my @nodepid;
my @nodeout;
my @childs;
our @sorted;

my $sleep = 10;

my $kill;
my $spawn;
my $max;
my $interactive;
my $ret = 0;
my $verbose;
GetOptions(
	"nodes=i" => \$nodes,    # numeric
	"kill=i"   => \$kill,      # numeric
	"max=i"   => \$max,      # numeric
	"spawn=i"   => \$spawn,      # numeric
	"interactive"   => \$interactive,      # numeric
	"verbose"  => \$verbose
  )   # flag
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


use Term::ANSIColor;


sub print_help {

	my $bold =  color('bold');
	my $normal = color('reset');
	print "commands:\n";
	print "${bold}start_node:${normal}\tStart one node\n";
	print "${bold}s:${normal}\t\tStart one node\n";
	print "${bold}start_node n t:${normal}\tStart n nodes with t seconds pause in between spawn\n";
	print "${bold}status:${normal}\t\tPrint Ring status\n";
	print "${bold}verbose:${normal}\tToggle verbose mode\n";
	print "${bold}kill n:${normal}\t\tKill n random nodes\n";
	print "${bold}kill:${normal}\t\tKill one node\n";
	print "${bold}k:${normal}\t\tKill one node\n";
}

if($interactive) {

	#	use Curses::UI;

	#my $ui = new Curses::UI( -color_support => 1 );
	#my $window = $ui->add(
	#'window1', 'Window',
	#-border => 1,
	#);
	#my $text = "No ";
	#$text = $window->add(
	# 'label1', 'Label',
	# -text => $text,
	#);

	#$ui->set_binding( sub{ kill_nodes(); exit; } , "\cC");
	#$ui->set_binding( sub{ my $count = $ui->question('How many?:'); if(defined ($count) && looks_like_number($count)) {start_nodes($count+0,$lo,1,1); } } , "a");
	#$ui->set_binding( sub{ start_nodes(1,$lo,0,1) } , "s");
	#$ui->set_binding( sub{ toggle_verbose() } , "v");
	#$ui->set_binding( sub{
	#    if(check_ring() == 0) {
	#        my $str = ring_to_str(); $str = "Ring is in sync: $str";
	#        $ui->dialog($str);
	#    }
	# } , "p");
	#$ui->mainloop();
	my $s = IO::Select->new();
	$s->add(\*STDIN);
	print ">";
	select()->flush();

	my $exit = 0;
	while ($end <= 0) {
		if ($s->can_read(.5)) {
			chomp(my $line = <STDIN>);
			my @commands = split(';',$line);
			foreach $line (@commands) {
				$line =~ s/^\s+|\s+$//g;
				if($line eq "help") {
					print_help();
				} elsif($line eq "exit") {
					$exit = 1;
					last;
				} elsif($line eq "start_node" || $line eq "s") {
					start_nodes(1,$lo,0,0);
				} elsif($line =~ /start_node ([0-9]+) ([0-9]+)/g) {
					start_nodes($1,$lo,$2,0);
				} elsif($line eq "status") {
					my $err = check_ring();
					if(!$err) {
						if($verbose) {
							print Dumper(@sorted);
						}
						print ring_to_str()."\n";
						print "Ring is in sync\n\n";
					} else {
						print "Ring is not in sync $err sync errorss\n\n";
					}
				} elsif($line eq "verbose") {
					toggle_verbose();
				} elsif($line eq "kill" || $line eq "k") {
					kill_node();
				} elsif($line =~ /kill ([0-9]+)/g) {
					kill_node($1);
				} else {
					print "Unknown command $line\n";
					print_help();
				}
			}
			if($exit) {
				last;
			}
			print "\n>";
			select()->flush();
		}
	}
} else {
	start_nodes($nodes,$lo,1,0);
	my $c = 0;
	while($end == 0) {
		sleep 1;
		if($end > 0){
			last;
		}
		my $not_in_sync = check_ring();
		$c++;
		if($verbose) {
			print Dumper(@sorted);
			if(defined($max)) {
				print "Run $c/$max sync: $not_in_sync end: $end\n";
			}else {
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
}

kill_nodes();
exit($ret);


sub kill_nodes {
	print "Kill\n";
	for(my $i = 0;$i<@childs;$i++) {
		if(defined($childs[$i])) {
			print "Kill: $childs[$i]{pid}\n";
			system("kill $childs[$i]{pid}");
		}
	}
}


sub kill_node {
	(my $count) = @_;
	for(my $i = 0;$i < $count;$i++) {
		my $victim = rand(@childs);
		$childs[$victim]{killed} = 1;
		print "Kill $childs[$victim]{cmd} with pid  $childs[$victim]{pid}\n";
		system("kill $childs[$victim]{pid}");
		splice(@childs,$victim,1);
	}
}


sub toggle_verbose {
	if($verbose) {
		print "Toggle Verbose off\n";
		$verbose = 0;
	} else {
		print "Toggle Verbose on\n";
		$verbose = 1;
	}
}


sub start_nodes {
	(my $count, my $interface, my $sleep, my $silent) = @_;
	print "Start with $count nodes on interface $interface\n";
	my $nodes_exists = @childs;
	for(my $i = 0;$i<$count && $end == 0;$i++) {
		my $hash_index = $nodes_exists + $i;
		my $hex = sprintf("%X", $hash_index+1);
		my $rnd_master = $childs[rand @childs]{addr};
		$childs[$hash_index]{addr} = "::$hex";
		if($verbose) {
			print "ifconfig $interface inet6 add $childs[$hash_index]{addr}\n";
		}
		system("ifconfig $interface inet6 add $childs[$hash_index]{addr} > /dev/null 2>&1");
		$childs[$hash_index]{master_addr} = $rnd_master;
		$childs[$hash_index]{killed}  = undef;
		$childs[$hash_index]{cmd} = "";
		if($hash_index == 0) {
			$childs[$hash_index]{cmd} = "./example master $childs[$hash_index]{addr} silent";
		} else {
			$childs[$hash_index]{cmd} = "./example slave $childs[$hash_index]{addr} $rnd_master silent";
		}
		if($verbose) {
			print "$childs[$hash_index]{cmd}\n";
		}
		$childs[$hash_index]{pid}  = fork();
		$childs[$hash_index]{outname} = "./log/chord.$childs[$hash_index]{pid}.log";
		if(not $childs[$hash_index]{pid}) {
			exec($childs[$hash_index]{cmd});
			exit(0);
		}
		if($sleep > 0) {
			sleep($sleep);
		}
	}
}


sub ring_to_str {
	ring_sort();
	my $str = "";
	for(my $i = 0;$i<@sorted;$i++) {
		$str .= $sorted[$i]{me};
		if($i != @sorted-1) {
			$str .=  "->";
		}
	}
	return $str;
}


sub ring_sort {
	our @sorted =  sort { (defined($a->{me}) <=> defined($b->{me})) || $a->{me} <=> $b->{me} } @childs;
}


sub check_ring {
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
	ring_sort();
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
	return $not_in_sync;
}