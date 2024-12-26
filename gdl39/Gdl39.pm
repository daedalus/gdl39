#This is the Code to Manage the GDL39
package Gdl39;

use Time::HiRes qw(sleep);
use POSIX;
use IO::Handle;
use FileHandle;
use IO::Tty;
use Compress::Zlib qw(uncompress);
use Crypt::Blowfish_c_PP; # Pure Perl Pour Portability
use Data::Dumper;

use warnings;

my $DLE = chr(0x10);
my $ETX = chr(0x03);

my @key1 = (90,107,15,126,0xCB,50,85,0xAA);
my @key2 = (0xA5.102,0x9f,50,0xDA,103,0xAA,85);

our $floatreverse = 1;
if ( (unpack "f","\x00\x00\x80\x3f") > 0.5) {
    $floatreverse = 0;
};



# what do we do when we get a packet
my %dispatch;
# what do we do when we get a file
my %dispatch_file;

my %file_xref;
# file descriptor and IO::Handle
our $fd;
our $io;
our $debug = 0;
our $gps_debug = 0;
our $traffic_debug = 0;
our $weather_debug = 0;
our $max_packet_size = 255;
our @remote_version; # numbers and words
our @remote_id; # just numbers(serial?)

# data is the data portion of the packet in numeric form 1 byte per entry
our %data;
# 0_305: 0000  10 00 08 31 01 00 00 1c 00 00 00 aa 10 03         ...1..........

our $last_raw_read;


sub ary_to_bin {
    return pack ("C*",@_);
}    

sub bin_to_ary {
    return (unpack ("C*",$_[0]));
}    

sub to_int { 
    return (unpack("V",pack("C*",@_)));
};

sub pull {
    my ($x,$n) = @_;
    return (substr($x,$n) , substr($x,0,$n) );
};

sub pullu {
    my ($x, $n , $t) = @_;

    if ($t =~ /[fd]/ && $floatreverse) {
    return (substr($x,$n) , unpack($t,(reverse substr($x,0,$n))));
    } 

    return (substr($x,$n) , unpack($t,substr($x,0,$n)));

};

sub dump_packet {
    print dump_packet_str(@_);
    print "\n";

};

sub dump_packet_str {
    my $out = "";
    my $c = 0;
    my $str="";
    for $x (@_) {
	if ($c %32 == 0 ) {
	    if ($c > 0 ) {
		$out .= " ".$str."\n";
		$str="";
	    }
	    $out .= sprintf "%04X ",$c;
	}

	$out .= sprintf "%02X ",$x;
	$c++;
	$z = chr($x);
	if ($z =~ /[[:graph:]]/ ) {
	    $str.= $z;
	} else {$str .= ".";};
    };
    while ($c %32 != 0 ) {
	$out .= "   ";
	$c++;
    };


    $out .= " ".$str."\n";
    $d = "";
    if ( @_ > 6 && 
	$_[6] == 0x78 && $_[7] == 0x5e ) {
	for $jz (6 .. $#_ ) {
	    $d .= chr($_[$jz]) ;
	};
	$out .= "Compressie:".length($d)."\n";
	$foobar =  uncompress($d);

	my @goofie  = unpack "C*",$foobar;

	$out .= dump_packet_str(@goofie);
    };

    return($out);


};



sub send_msg {
    my $msg_id=shift @_;
    my $ext_id=shift @_;
    my $msg=shift @_;
    if ($debug) {print "Send: $msg_id , $ext_id , " . length($msg)."\n";};

    my @array ; 
    push @array , $msg_id;

    if ($msg_id == 0 ) {
    push @array , (length($msg)+2) %256;
    if ($max_packet_size > 255 ) {
    push @array , int((length($msg)+2) / 256);
    };
    push @array , $ext_id %256;
    push @array , int($ext_id / 256);
    } else {
    push @array , (length($msg)) %256;
    if ($max_packet_size > 255) {
    push @array , int((length($msg)) / 256);
    };
};

    push @array,(unpack "C*",$msg);
    $csum=0;
    for my $ck (@array) {
	if ($debug) {printf "%02X ", $ck; };
	$csum = ($csum + $ck ) & 255;
    };
    $csum = (255 - $csum) + 1 ;
    push @array, $csum;
    if ($debug) {printf " CK: %02X\n", $csum; };

    $io->syswrite($DLE, 1);

        $outstr = pack ("C*",@array);
    $outstr =~ s/$DLE/$DLE$DLE/gs;

    $io->syswrite($outstr, length($outstr));
    $io->syswrite($DLE.$ETX, 2);



};


sub read_msg {
# timeout: undef: wait forever, 0 don't wait, >0 wait in seconds
    my ($timeout) = @_;
    my $c ;
    my $rv;
    my @packet;
    my $state=0;
    my $done = 0;
$rin = $win = $ein = "";
#vec($win,$fd,1) = 1;
# only check for read
vec($rin,$fd,1) = 1;

my ($nfound,$timeleft) = select($rout = $rin , $wout=$win , $eout=$ein ,$timeout) ;
    if ($nfound <= 0 ) {return undef;};


    if ($debug>10) {    print "Rec Raw: "; };
    while (!$done) {


	$rv = $io->sysread($c,1);
	if (!defined $rv || $rv == 0 ) {
	    die "Unexpected read failure: $rv $!\n";
	};
	my $co = ord($c);
	if ($debug >10) {printf "%02x ",$co;};
	
    if ($state == 0 && $c eq $DLE ) {
	push @packet,$co;
	$state++;
	next;
    };
    if ($state == 1 && $c ne $DLE ) {
	push @packet,$co;
	next;
    };
    
    if ($state == 1 && $c eq $DLE ) {
	push @packet,$co;	
	$state++;
	next;
    };
    # stuffed, ok
    if ($state == 2 && $c eq $DLE ) {
	$state=1;
	next;
    };
    if ($state == 2 && $c eq $ETX ) {
	push @packet,$co;
	$done=1;
	next;
    };
    # previous DLE with no ETX, probably mis-sync, reset
    if ($state == 2 ) {
	@packet = (16,$x) ;
	$state = 1;
	next;
    };

    };
    $last_raw_read = pack("C*",@packet);


    my $msg_id = $packet[1];
    my $ext_id = "";
    my $length = -1;
    my $start=-1;
    if ($msg_id == 0) {
	if ( $max_packet_size > 255 ) {
	    $length = unpack("v",(pack "C*" ,@packet[2,3]));
	    $ext_id = unpack("v",(pack "C*" ,@packet[4,5]));
	    $start=6;
	} else {

	    $length = $packet[2];;
	    $ext_id = unpack("v",(pack "C*",@packet[3,4]));
	    $start=5;
	};
    } else {
	if ( $max_packet_size > 255 ) {
	    $length = unpack("v",(pack "C*" ,@packet[2,3]));
	$start=4;
	} else {
	    $length = $packet[2];
	$start=3;

	};
    };  
    if ($debug>10) {print "\n";};

    return ($msg_id,$ext_id,$length,@packet[$start .. $#packet - 3] ) ;
};

sub send_raw {
    my ($outstr) = @_;
    $io->syswrite($outstr, length($outstr));
};

# send ack (6)
sub send_ack {
    my ($msg_id,$ext_id) = @_;
    my @msgarray;
if ($msg_id == 0 ) { 
    push @msgarray,0x00,0x00;
    push @msgarray,($ext_id %256),int($ext_id/256);
} else {
    push @msgarray,$msg_id,0x00;
};

    
    if ($debug) {print "Ack: $msg_id "; };
    my $msgt = pack("C*",@msgarray);
    
    
    send_msg(0x06,0,$msgt);
};

sub send_255 { 
# send the 0xff response
    my $msgt = "\x42\x00\x13\x00Abcdef Ghijk\x00";

    
    send_msg(0xff,0,$msgt);
};



sub send_34 {
# this is some crypt string to prove our identity...
    if ($debug) {print "Send 34\n";} ;
    my $blowfish;


    my @dt = unpack("C*",$data{'traffic'});

my @cryptbase = (@remote_version[2..3],
		 $dt[24],$dt[25],$dt[22],$dt[23],$dt[26],$dt[28],
		 @remote_id[0..3],
		 @remote_version[0..1],
		 @{$data{'0_305'}}[2..3]
    );
    if ($debug) {print "Cryptbase: ";
    for my $k (@cryptbase) {
		       printf "%02X ",$k;
    };
    print "\n";
    };

    $blowfish = new Crypt::Blowfish_c_PP(ary_to_bin(@cryptbase));
    my @to_encrypt = split // , "Abcdef Ghijk" ;
    
    for my $i (0..55) {if (!defined $to_encrypt[$i]) {$to_encrypt[$i] = chr(165);};

};

    my $ciphertextBlock = "";
    for my $i (0,8,16,24,32,40,48) {
	my $x =	reverse(@to_encrypt[$i..($i+7)]);

    dump_packet(unpack("C*",$x));
	$ciphertextBlock .= reverse($blowfish->encrypt( $x ) );
    };

	# this is 8 bytes, no need to do anything else
    my $c = $ciphertextBlock;
    my $cryptit = reverse(ary_to_bin(@key1));
    
    $blowfish = new Crypt::Blowfish_c_PP($c,11);
    $ciphertextBlock =reverse  $blowfish->encrypt($cryptit);
    
    if (!defined($_[0]) ) {	send_msg(0,34,$ciphertextBlock);
    };
    return $ciphertextBlock;
    
    
};

sub parse_traffic {

# take a raw(uncompressed) traffic structure and turn it into hashes(and YAML?)
    my $t = $data{'traffic'};
    
    my %result ; # result hash
    $result{'meta'} = {};
    $r = $result{'meta'};

    ($t , $r->{'major'}) = pullu($t,2,"v");
    ($t , $r->{'minor'}) = pullu($t,2,"v");
    ($t , $r->{'adsstat'}) = pullu($t,1,"C");
    ($t , $r->{'tcasinst'}) = pullu($t,1,"C");
    ($t , $r->{'tcasmode'}) = pullu($t,1,"C");
    ($t , $r->{'age'}) = pullu($t,4,"f");
    ($t , $r->{'arrivalt'}) = pullu($t,4,"f");
    ($t , $r->{'airborne'}) = pullu($t,1,"C");
    ($t , $r->{'csa'}) = pullu($t,1,"C");
    ($t , $r->{'sfcia'}) = pullu($t,1,"C");
    ($t , $r->{'time'}) = pullu($t,4,"f");
    ($t , $r->{'month'}) = pullu($t,1,"C");
    ($t , $r->{'day'}) = pullu($t,1,"C");
    ($t , $r->{'year'}) = pullu($t,2,"v");
    ($t , $r->{'hour'}) = pullu($t,2,"v"); # apparently more than 255 hours are possible in a day....
    ($t , $r->{'min'}) = pullu($t,1,"C"); 
    ($t , $r->{'sec'}) = pullu($t,1,"C"); 
    $result{'self'} = {};
    $r = $result{'self'};
    ($t , $r->{'lat'}) = pullu($t,8,"d");
    ($t , $r->{'lon'}) = pullu($t,8,"d");
    ($t , $r->{'speed'}) = pullu($t,4,"f");
    ($t , $r->{'track'}) = pullu($t,4,"f");
    ($t , $r->{'hdg'}) = pullu($t,4,"f");
    ($t , $r->{'palt'}) = pullu($t,4,"f");
    ($t , $r->{'galt'}) = pullu($t,4,"f"); # geometric
    ($t , $r->{'aclen'}) = pullu($t,4,"f");
    ($t , $r->{'acwid'}) = pullu($t,4,"f");
    ($t , $r->{'hfom'}) = pullu($t,4,"f");
    ($t , $r->{'crab'}) = pullu($t,4,"f"); 
    ($t , $r->{'addr'}) = pullu($t,4,"V"); 
    ($t , $r->{'unk1'}) = pullu($t,1,"C"); 
    ($t , $r->{'call'}) = pullu($t,8,"A8");  # guess
    ($t , $r->{'fltid'}) = pullu($t,8,"A8");  # guess
    ($t , $r->{'airborne'}) = pullu($t,1,"C");
    ($t , $r->{'shadow'}) = pullu($t,1,"C");    
    ($t , $r->{'trkunc'}) = pullu($t,1,"C");    
    ($t , $r->{'validflags'}) = pullu($t,4,"V");
    ($t , $r->{'datum'}) = pullu($t,1,"C");    
    ($t , $r->{'unk2'}) = pullu($t,1,"C");    
    $r = $result{'meta'};
    
    if (length $t < 4 ) {
	$r->{'numtarget'} = 0;
    } else {
        ($t , $r->{'numtarget'}) = pullu($t,4,"V");
    };
    while (length $t > 4) {
	my $id ;
        ($t , $id) = pullu($t,4,"V");
	push @{$result{'idlist'}} , $id;
    $result{$id} = {};
	$r = $result{$id};
    ($t , $r->{'addr'}) = pullu($t,4,"V"); 
    ($t , $r->{'trksrc'}) = pullu($t,1,"C"); 

    ($t , $r->{'datalink'}) = pullu($t,1,"C"); 
    ($t , $r->{'addrqual'}) = pullu($t,1,"C"); 
    ($t , $r->{'airborne'}) = pullu($t,1,"C"); 
    ($t , $r->{'stateage'}) = pullu($t,4,"f");
    ($t , $r->{'idage'}) = pullu($t,4,"f");
    ($t , $r->{'aircap'}) = pullu($t,1,"C"); 
    ($t , $r->{'csacap'}) = pullu($t,1,"C"); 
    ($t , $r->{'sfciacap'}) = pullu($t,1,"C"); 
    ($t , $r->{'sfciaprio'}) = pullu($t,2,"v"); 
    ($t , $r->{'unk1'}) = pullu($t,1,"C"); 
    ($t , $r->{'lat'}) = pullu($t,8,"d");
    ($t , $r->{'lon'}) = pullu($t,8,"d");
    ($t , $r->{'closure'}) = pullu($t,4,"f");
    ($t , $r->{'palt'}) = pullu($t,4,"f");
    ($t , $r->{'galt'}) = pullu($t,4,"f"); # geometric
    ($t , $r->{'ralt'}) = pullu($t,4,"f"); # relative
    ($t , $r->{'rdir'}) = pullu($t,4,"f"); # relative direction
    ($t , $r->{'truedeg'}) = pullu($t,4,"f");
    ($t , $r->{'dist'}) = pullu($t,4,"f");
    ($t , $r->{'relbrg'}) = pullu($t,4,"f");
    ($t , $r->{'speed'}) = pullu($t,4,"f");
    ($t , $r->{'ewspeed'}) = pullu($t,4,"f");
    ($t , $r->{'nsspeed'}) = pullu($t,4,"f");
    ($t , $r->{'fpm'}) = pullu($t,4,"f");
    ($t , $r->{'relspeed'}) = pullu($t,4,"f");
    ($t , $r->{'reldeg'}) = pullu($t,4,"f");
    ($t , $r->{'cpanm'}) = pullu($t,4,"f");
    ($t , $r->{'cpasec'}) = pullu($t,4,"f");
	($t , $r->{'relaltsrc'}) = pullu($t,1,"C");
	($t , $r->{'truedirdatum'}) = pullu($t,1,"C");
	($t , $r->{'rangesrc'}) = pullu($t,1,"C");
	($t , $r->{'vvsrc'}) = pullu($t,1,"C");
	($t , $r->{'vvdir'}) = pullu($t,1,"C");
	($t , $r->{'alertstat'}) = pullu($t,1,"C");
	($t , $r->{'emittercat'}) = pullu($t,1,"C");
	($t , $r->{'emergprio'}) = pullu($t,1,"C");
	($t , $r->{'csaalert'}) = pullu($t,1,"C");
	($t , $r->{'tfciastat'}) = pullu($t,1,"C");
	($t , $r->{'corrstat'}) = pullu($t,1,"C");
	($t , $r->{'istisb'}) = pullu($t,1,"C");
    ($t , $r->{'aclen'}) = pullu($t,4,"f");
    ($t , $r->{'acwid'}) = pullu($t,4,"f");
    ($t , $r->{'call'}) = pullu($t,8,"A8");
    ($t , $r->{'fltid'}) = pullu($t,8,"A8");
    ($t , $r->{'validflags'}) = pullu($t,4,"V");
};

    $data{'traffic_hash'} = \%result;
};


# Ground Station log
$dispatch_file{"20"} = sub { 

    my $t = $data{'20'};
    
    my %result ; # result hash
    $result{'meta'} = {};
    $r = $result{'meta'};
    ($t , $r->{'count'}) = pullu($t,1,"C");
    ($t , $r->{'rate'}) = pullu($t,4,"V"); 

    $remaining = $r->{'count'};
    while (length $t > 4 && $remaining > 0 ) {
	my $id ;
        ($t , $id) = pullu($t,1,"C");
	push @{$result{'idlist'}} , $id;
	$result{$id} = {};
	$r = $result{$id};
	
	($t , $r->{'lat'}) = pullu($t,8,"d");
	($t , $r->{'lon'}) = pullu($t,8,"d");
	($t , $r->{'rate1'}) = pullu($t,4,"V"); 
	($t , $r->{'rate2'}) = pullu($t,4,"V"); 
	$remaining--;
    };
    
    $data{'20_hash'} = \%result;
};

for my $df ( 1..11) {

$dispatch_file{$df} = sub {dispatch_segmented($df);};
};






sub dispatch_segmented { 
    my ($id) = @_;
    decode_segmented($id);
    if (defined $data{$id.'_hash'} ) {
	my $d = $data{$id.'_hash'};
	for my $i (@{$d->{'seglist'}} ) {
	    if ($debug) {print "Decode: $i\n";};
	    if (defined $d->{$i}{'data_uncompressed'} ) {
		$d->{$i}{'data_raw'} = undef;
		$d->{$i}{'data'} = dump_packet_str(
		      unpack("C*",  $d->{$i}{'data_uncompressed'} ));
		$d->{$i}{'data_uncompressed'} = undef;
	    } else {
		$d->{$i}{'data'} = dump_packet_str(
		    unpack("C*", $d->{$i}{'data_raw'} ));
		$d->{$i}{'data_raw'} = undef;
	    };
	};
    };
};



sub decode_segmented {
# extract a segmented file
    my ($id ) = @_;
    if (!defined $data{$id."_raw"} ) {
	return undef;
    };
    my %result ; # result hash
    $result{'meta'} = {};
    $r = $result{'meta'};
    
    my $t = $data{$id."_raw"} ; 
    
#    ($t , $r->{'packetid'}) = pullu($t,4,"V"); 
#    ($t , $r->{'packetid2'}) = pullu($t,2,"v"); 
    
    ($t , $r->{'size'}) = pullu($t,4,"v"); 
    ($t , $r->{'numseg'}) = pullu($t,4,"v"); 
    my $segno = 0;
    my $numseg = $r->{'numseg'};
	if ($debug) {print "Segmented: $numseg\n";}
    while (length $t > 4 && $segno < $numseg ) {
	push @{$result{'seglist'}} , $segno;
	$result{$segno} = {};
	$r = $result{$segno};
	
	($t , $r->{'offset'}) = pullu($t,4,"V");
	($t , $r->{'length'}) = pullu($t,4,"V");
	if ($debug) {print "Segment: $segno ".$r->{'offset'}." ".$r->{'length'}."\n";}
	# put the data in
	$r->{'data_raw'} = substr($data{$id."_raw"} , $r->{'offset'} , $r->{'length'} );
	
	if (substr($r->{'data_raw'},0,2) eq "\x78\x5e" ) {
	    $r->{'data_uncompressed'} = uncompress($r->{'data_raw'});
	};
	$segno++;
    };
    
    $data{$id.'_hash'} = \%result;    
    
};








sub decode_traffic {
    if (substr($data{'traffic_raw'},0,2) eq "\x78\x5e" ) {
	$data{'traffic'} = uncompress($data{'traffic_raw'});
	parse_traffic();
	$data{'traffic_new'} = 1;
    } else {
	warn "No traffic to decode";
	};
};




sub send_traffic_req {
    if ($traffic_debug) {print "TFCREQ: ";};


my $msgh = "00 00 CE 02 00 00 15 00 00 00 00 00 00 00 2F 52 41 4D 2F 54 52 41 46 46 49 43 5F 53 54 41 54 45";
$msgh =~ s/ //g;
$msgt = pack("H*",$msgh);

send_msg(0,0,$msgt);
};


sub send_ground_station_log_req {
    if ($debug) {print "GSLREQ: ";};

my $msgh = "00 00 ce 02 00 00 14 00 00 00 00 00 00 00 2f 52 41 4d 2f 47 52 4f 55 4e 44 5f 53 54 41 54 49 4f 4e 5f 4c 4f 47 ";


$msgh =~ s/ //g;
$msgt = pack("H*",$msgh);

send_msg(0,0,$msgt);
};


sub send_x_req {
    my ($val,$str) = @_;
    if ($debug) {print "$str: ";};
# type $val(decimal)
my $msgh = sprintf("00 00 ce 02 00 00 %02x 00 00 00 00 00 00 00", $val);

$msgh =~ s/ //g;
$msgt = pack("H*",$msgh);

send_msg(0,0,$msgt.$str);
};




sub send_packet_size_change {
# "0x10,0x00,0x04,0x10,0x10,0x00,0x00,0x08,0xe4,0x10,0x03) ;

    my $msgt = "\x00\x08"; # 2048... maybe

send_msg(0,0x10,$msgt);
};

sub send_packet_size_finalize {
#@msgarray = (0x10,0x0a,0x02,0x00,0x3a,0x00,0xba,0x10,0x03);
# send this raw since it uses the extended format before the packet size change
    send_raw("\x10\x0a\x02\x00\x3a\x00\xba\x10\x03");
};

$dispatch{"0_2"} = sub {
    my ($msg_id,$ext_id,@msg_ary) =@_ ;
    # response to a transfer

    my $msgt = pack("C*",($ext_id % 256,0x00,@msg_ary[0..5]));
# put the file away

    my $xr = $file_xref{$msg_ary[0]} ;
    my $type = $xr->{'type'};
    my $size = $xr->{'size'};
    my $thispacketsize = (scalar @msg_ary) - 6 ; 
    if (!defined $data{$type."_temp" } ) {
	$data{$type."_temp"} = substr(ary_to_bin(@msg_ary),6);
    } else {
	$data{$type."_temp"} .= substr(ary_to_bin(@msg_ary),6);
    } ;
	

# send ack
    send_msg(0,8,$msgt);

    if (length $data{$type."_temp"} < $size) {
	if ($debug) { print "Incomplete: ".(length $data{$type."_temp"})." ".$size."\n"; }
	return;
    };
	if ($debug) { print "Complete: ".(length $data{$type."_temp"})." ".$size."\n"; }
    my $raw = $data{$type."_temp"} ;

# only dispatch if the file is done

    if ($type == 21 ) {
	$data{'traffic_raw'}=$raw;
	if ($traffic_debug) {print "Handoff: decode_traffic()\n";};
	decode_traffic();
    } else {
	if ($debug) {print "Parse/Dispatch: $type\n";}
	$data{$type."_raw"} = $raw;
	if (substr($raw,0,2) eq "\x78\x5e" ) {
	    $data{$type} = uncompress($raw);
	};
	$data{$type."_new"} = 1;
	if (defined $dispatch_file{$type} ) {
	    if ($debug>10) {
		print "*\n";
		dump_packet(bin_to_ary $raw);
		print "**\n";
	    };
	    
	    &{$dispatch_file{$type}}();	    
	    
	} else {
	    $data{$type."_hash"} = dump_packet_str(bin_to_ary $raw);
	    
	};
    }
    
};

sub new_gps {return ($data{"GPGGA_new"} && $data{"GPRMC_new"});}
sub reset_gps {
    $data{"GPGGA_new"}=0;
    $data{"GPRMC_new"}=0;
};


$dispatch{"249_"} = sub {
    send_255();
};


$dispatch{"0_305"} = sub {
    my ($msg_id,$ext_id,@msg_ary) =@_;
	$Gdl39::data{'0_305'}=\@msg_ary;
};

$dispatch{"0_307"} = sub {
    my ($msg_id,$ext_id,@msg_ary) =@_;
    if ($gps_debug) {dump_packet(@msg_ary);};
    my $sentence= pack("C*",@msg_ary);
    if ($sentence =~ /\$GPGGA/ ) {
	if ($gps_debug) {print "Upd: GPGGA\n";};
	$data{'GPGGA'} = $sentence;
	$data{'GPGGA_new'} = 1;
    };

    if ($sentence =~ /\$GPRMC/ ) {
	if ($gps_debug) {print "Upd: GPRMC\n";};
	$data{'GPRMC'} = $sentence;
	$data{'GPRMC_new'} = 1;
    };
};


$dispatch{"0_32"} = sub {
# 4 character ID of some sort, make something up
    send_msg(0,33,"\xde\xad\xbe\xef");
};

$dispatch{"0_1"} = sub {
    my ($msg_id,$ext_id,@msg_ary) =@_;
   # if ($msg_ary[14] == 11 ) {
	# ack the file
    $file_xref{$msg_ary[16]}->{'type'} = $msg_ary[14];
    $file_xref{$msg_ary[16]}->{'size'} = to_int(@msg_ary[2..5]);
    if ($debug) {print "XR: ".$msg_ary[14]." ".
		     ($file_xref{$msg_ary[16]}->{'size'})."\n";
	     
    }
    if ($file_xref{$msg_ary[16]}->{'size'} == 0 ) {
	if ($debug) {dump_packet(@msg_ary);};

	return;
	};

	send_msg(0,8,pack("C*",(0x01,0x00,$msg_ary[16],0,0,0,0,0)));
    #};
};





# big list of stuff we ack
# may be safe to ack everything except ack or nak....

my %ack_hash;
for my $i ("255_","10_","253_","249_","0_305","0_32","0_33","0_34","0_309") {
    $ack_hash{$i}=1;
};

sub check_and_ack {
    my ($m,$e) = @_;
	$ck = $m."_".$e;

    if (defined $ack_hash{$ck} ) {
	send_ack($m,$e);
	return(1);
    };
    return(0);
};


sub check_and_dispatch {
    my ($m,$e,@msga) = @_;
	$ck = $m."_".$e;
    if ($debug) {print "Ck: $ck\n"; };
    if (defined $dispatch{$ck} ) {
	if ($debug) {print "Dispatch\n";};
	&{$dispatch{$ck}}($m,$e,@msga);
	return(1);
    };
    return(0);
};






sub init {
    my ($device) = @_;

    $fd =  POSIX::open($ARGV[0], &POSIX::O_RDWR |  &POSIX::O_NOCTTY) ;
    if (!defined $fd) {die "No fd";};
    
    $io = IO::Handle->new_from_fd($fd,"a");
    my $ti = new POSIX::Termios;
    $ti->getattr($fd);
    $ti->setcflag(&POSIX::CS8 | &POSIX::CREAD );
    $ti->setlflag(0);
    $ti->setiflag(0);
    $ti->setoflag(0);
    
    my $b = B9600;
    if (defined &B460800 ) {$b = B460800;};
    
    $ti->setispeed($b);
    $ti->setospeed($b);
    $ti->setattr($fd,&POSIX::TCSANOW);
}

sub close {
    POSIX::close($fd);
};



1;
