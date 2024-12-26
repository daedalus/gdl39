#! /usr/bin/perl
use FindBin;
use lib $FindBin::Bin;
use Time::HiRes;
use Data::Dumper;

$|=1;

use Gdl39;

while(1) {
    eval {

$Gdl39::debug=1;
# init the device
Gdl39::init($ARGV[0]);


my $wake = 20;
    my $done = 0 ;
my $stage=0;
my %sent_check;
while (!$done) {
# first loop, setup device
    if ($wake<0 && $stage == 0 ) {
	die "Could not wake";
    };
    $wake--;

    print "Pre_Rec: $stage\n";

    my ($msg_id,$ext_id,$msg_length,@msg_ary) = Gdl39::read_msg(0.1);
    if (!defined $msg_id || ! defined $ext_id) {next;};

  Gdl39::check_and_ack($msg_id,$ext_id);

# request for our text name or version information
    if ($msg_id == 249 || ($msg_id == 0 && ($ext_id==32 || $ext_id==305)) ) {
	# respond in kind

	Gdl39::check_and_dispatch($msg_id,$ext_id,@msg_ary);
	$sent_check{$msg_id." ".$ext_id} = 1;
    };

	

    if ($stage==0 && $msg_id == 10 && $msg_ary[0]==178) {
	# send basically the same
	Gdl39::send_msg(10,0,"\xb2\x00");
	# now send the 249 request
	Gdl39::send_msg(249,0,"");


	$stage++;
    };

    if ($stage==1 && $msg_id==255 ) {
	# this should have auto-acked above
	# received the version stuff, store it
	@Gdl39::remote_version=@msg_ary;
	# Send a request 32
	Gdl39::send_msg(0,32,"");
	
	# apparently we now send a traffic request
	Gdl39::send_traffic_req();
	  
	$stage++;
    };
    if ($stage==2 && $ext_id == 33 ) {
	@Gdl39::remote_id=@msg_ary;
    }
    if ($stage==2 && $ext_id == 1 ) {
	# this is an ack that yes we do want the traffic
	Gdl39::check_and_dispatch($msg_id,$ext_id,@msg_ary);
    };
    if ($stage == 2 && $ext_id == 2) {

#	$Gdl39::data{'traffic'}=Gdl39::ary_to_bin(@msg_ary);
	# special 'ack'
	Gdl39::check_and_dispatch($msg_id,$ext_id,@msg_ary);
	$stage++;
	# traffic complete
    };
	if ($stage == 3 && defined $Gdl39::data{'traffic'} && 
	    $sent_check{"249 "} && $sent_check{"0 32"} && $sent_check{"0 305"}) {
	    # send whatever this is
#	    Gdl39::send_msg(0,34,"\x4c\x46\x66\xaa\x1e\x00\x1e\x8a");
	    Gdl39::send_34();
	    $stage++;
	}
	if ($stage == 4 && $msg_id==0 && $ext_id==34) {
	    $done=1;
	    # next loop we increase the packet size
	};




};


$stage = 0;
$done=0;
my $ack_count=0;
my $packetchangeraw = "\x10\x0a\x02\x00\x3a\x00\xba\x10\x03" ;
while (!$done) {
# second loop, increase packet size
# in thos loop, we do nothing except the packet size switch
    print "Phase2: Stage: $stage Ack_count: $ack_count\n";
    my ($msg_id,$ext_id,$msg_length,@msg_ary) = Gdl39::read_msg(0.1);
    # 0x8000 hex, 2048 bytes

    if ($stage == 0 ) {Gdl39::send_msg(0,16,"\x00\x08");$stage++;};
    if ($stage == 1 && defined $msg_id && $msg_id == 0 && $ext_id == 17 ) {
	Gdl39::send_ack(0,17);
	$stage++;
    };
    if ($stage == 2) {
	Gdl39::send_raw($packetchangeraw);
	$stage++;
	next;
    };
    if ($stage==3 && $msg_id == 6 && $msg_ary[1] == 10 ) {
	$ack_count++;
    };
    if ($stage == 3 && $ack_count < 4 ) {
	print "Send: Packet size change\n";
	Gdl39::send_raw($packetchangeraw);
	Gdl39::dump_packet(unpack("C*",$packetchangeraw));
    };
    if ($stage == 3 && $ack_count >= 4 ) {
	$Gdl39::max_packet_size=2048;
	$done=1;
    };






};



my $gps_stage=0;
my $traffic_stage=0;
my $req = {
    20 => {
	    'timeout' => 10,
	    'stage' => 0,
	    'req_dispatch' => \&Gdl39::send_ground_station_log_req,
	    },



    'traffic' => {
	    'timeout' => 3,
	    'stage' => 0,
	    'req_dispatch' => \&Gdl39::send_traffic_req,
	    },
};
my $keynum = 1;
for $k ( '/RAM/REG_NEXRAD',
	 '/RAM/CONUS_NEXRAD',
	 '/RAM/SUA',
	 '/RAM/W_T_ALOFT',
	 '/RAM/AIRMET',
	 '/RAM/SIGMET',
	 '/RAM/METAR',
	 '/RAM/GRPH_METAR',
	 '/RAM/NOTAM',
	 '/RAM/PIREP',
	 '/RAM/TAF'
    ) {
    $req->{$keynum} = {
	    'timeout' => 29+$keynum,
	    'stage' => 0,
	    'req_dispatch' => \&Gdl39::send_x_req,
	    'args' => [ $keynum,$k],
    };
    $keynum++;

};


my $weather_stage=0;

my $last_traffic=0; # latest of request or received so we don't repeat if we're not 
my $last_ground_station=0; # latest of request or received so we don't repeat if we're not 
# seeing results

$Gdl39::traffic_debug=0;
$Gdl39::gps_debug=0;


while (1) {
# main loop, request stuff and output it

    my ($msg_id,$ext_id,$msg_length,@msg_ary) = Gdl39::read_msg(0.4);
    my $t = Time::HiRes::time();
    if (defined $msg_id && defined $ext_id) {
	Gdl39::check_and_ack($msg_id,$ext_id);
	Gdl39::check_and_dispatch($msg_id,$ext_id,@msg_ary);
    };

    if ($gps_stage > 1 && Gdl39::new_gps()) {
	Gdl39::reset_gps();
	print "GPS: ".$Gdl39::data{"GPGGA"};
	print "GPS: ".$Gdl39::data{"GPRMC"};
    };
    if ($gps_stage == 1 ) {
	# request GPS
	# 1 hz, GPGGA and GPRMC
	Gdl39::send_msg(0,306,"\x01\x03");
	$gps_stage++;
    };
    if ($gps_stage == 0 ) {
	# request Pressure altitude enable(unverified)
	# this seems to correspond to the 'Pressurized Cabin'
	# box in the GUI. I guess the device has an on-board barometer.

	Gdl39::send_msg(0,309,"\x01");
	$gps_stage++;
    };


    for my $i (keys %$req) {
	my $r = $req->{$i};
    if ($r->{'stage'} >0 ) {
	if (	$Gdl39::data{$i.'_new'} ) {
	    print "$i: \n";
    print Dumper($Gdl39::data{$i.'_hash'});
	    $r->{'lastreq'} = $t;
	$Gdl39::data{$i.'_new'} = 0;
	} else {
	    if (defined $r->{'lastreq'} && $r->{'lastreq'} > 0 
		&& $t - $r->{'lastreq'} > $r->{'timeout'}) {
		my @a;
		if (defined $r->{'args'} ) {
		    @a = @{$r->{'args'}};
		};
		&{$r->{'req_dispatch'}}(@a);
	    $r->{'lastreq'} = $t;
	    };
	};
    };



    if ( $r->{'stage'} == 0 ) {
	$Gdl39::data{$i.'_new'} = 0;
		my @a;
		if (defined $r->{'args'} ) {
		    @a = @{$r->{'args'}};
		};
		&{$r->{'req_dispatch'}}(@a);
	$r->{'stage'}++;
	$r->{'lastreq'} = $t;
    };
    };




};
    

    } ;
    if ($@) {print $@."\n"};

    Gdl39::close();
    sleep 10;
};



