# gdl39
GDL39 Protocol

DISCLAIMER: I'm not the author, I don't know who it is. I just uploaded this for research purposes.

Quick protype, written in perl, proof of concept only.

This documents the protocol as used by the Bluetooth Serial Profile(Standard RFCOMM)

General:
Packets are delimited by 0x10 id length1 length2 ext1 ext2 .... checksum 0x10 0x03

If 'id'=0 then extended ID is in use, ext1 low byte and ext2 high byte. These are included in payload length, if id is != 0 then the ext bytes are omitted. If any non delimiter byte is a 0x10 then double it, do NOT include this double in the length count.
Length is only 2 bytes if the max packet size has been increased, at initial connection time the length is 1 byte.

Checksum is exactly as specified in the Garmin protocol for all their other devices, or look at the code, above.

iOS Protocol:
After reviewing the docs for the 5th or 6th time, it appears that as a developer you can
develop to the GDL39(or any MFI device) you cannot use it without the blessing of the
hardware vendor. So, it's doubtful that Garmin is ever going to allow that.

It appears the the iOS protocol for the GDL39 is exactly the same as the Bluetooth SPP/RFCOMM protocol but using the iOS ExternalAccessory.framework.

The GDL39 enumerates with 4 protocols(EASession protocolString):

com.garmin.gdl39_a , com.garmin.gdl39_b , com.garmin.gdl39_c , com.garmin.gdl39_d
 
Initial testing show these 4 perform the same, perhaps to allow multiple running programs to
connect at the same time(untested).

Serial Port:
The serial port defaults to 9600, with the same protocol described below working. I expect the rate can be changed using the same protocol as other
Garmin devices, but I didn't bother coding it up to check.(The described protocol seems very similar to what is used to change the size below.)

Windows Tools:

The Garmin WebUpdater seems to be able to update the device over both serial to USB and Bluetooth connections. Or at least
the device is recognized and says the firmware is up to date on both connections.



Handshake:

By far the most obnoxious part of the GDL39 is the handshake 'protocol'.

To prove the application identity it takes a few bytes the remote end sends. Encrypts them a couple
times and sends them back.

(Full source is in Gdl39.pm)

After receiving the 255 packet(identity data shorts and text), the 0,33 packet(integer ID)
a traffic response for ourselves(just uses the time contained there) and the 0,305 packet(?)

The following 'magic' is done:
Cat the 255 packet bytes 2,3
The year(little endian short),month,day,hour,minute(bytes)
the remote ID as provided(packet 0,33)
The 255 packet bytes 0,1
The 0,305 packet bytes 2+3(some sort of counter)

Use this as the key to Blowfish to encrypt the string you sent as the text in packet 255 earlier
(in response to the 249 inquiry) padded to 56 bytes with 165(decimal).
Encrypt this with blowfish, 16 round in ECB mode, 8 bytes per block. But reverse the bytes within a block before encrypting them and then once encrypted reverse the output bytes too.
reverse( encrypt(reverse(1,2,3,4,5,6,7,8)) 
For each of the 7 blocks of 8 bytes each. The block ordering is kept consistent.

Then feed that crypted text into another blowfish as a 56 byte key, this time 11 round(why? I have no idea)
Encrypting the value(decimal bytes):
 (90,107,15,126,203,50,85,170)
But first reverse it, then encrypt it, and then reverse that output,
then send it to the remote in a packet type 0,34
If all goes well you get an ack(6) and a 0,34 back with the remote signature, just ack it and move on.


Now, after all that, you'll want to negotiate a larger packet size, which is much simpler.

(Read the Code)

Then enable GPS
Send a message type 0,306 with payload of 2 bytes, first byte is update rate(1 or 5 Hz) second byte is which sentences to enable(bit 1: GPGGA, bit 2: GPRMC, bit 3: GPGSA) normal seems to be 3(1+2) and 7 gives you all 3. These are returned in mesage type 0,307 at the update rate specified.

File Requests:
File requests are a 3(ish) step process.
Request the file ( 0,0 ) then "00 27 00 00 00 00 00 CE 02 00 00 xx 00 00 00 00 00 00 00"
and then the filename appended.
xx is the ID you'll use to correlate the requested file with the returned data.

Then you'll receive a 0,1 packet with various data, byte 14 being your requested ID, byte 16 being the handle that identifies this transaction and
bytes 2-5 the file size(if 0, something went wrong, other bytes indicate why it failed)
You'll ack the 0,1 with a 0,8 packet ahd the same handle number.

Then you'll get data in a series of 0,2 packets. Append each one to the data until you get the full length.
Each data packet must be acked again with 0,8.
(Code: send_x_req, dispatch{"0_1"} , dispatch{"0_2"} )



Then ask for traffic when you want it.
Basically, just send a file request for /RAM/TRAFFIC_STATE
This can also be a callback(the system will let you know when traffic is ready, unconfirmed and not yet 
coded.


Then decode the traffic:
Take the returned packet, use deflate to expand it and then decode.

All data little endian(except actual strings), ss short(2), ii int(4) ff float(4) dd double(8)
bb byte(1) 
aa ascii(variable)
lat and lon are in radians.


0000 01 00 00 00 03 00 04 00 00 66 3E 00 CE 96 46 04 04 00 00 CE 96 46 08 04 DC 07 17 00 31 31 DD DD  
     ss 22 ss 22 bb bb bb ff 22 33 44 ff 22 33 44 bb bb bb ff 22 33 44 bb bb ss 22 ss 22 bb bb dd 22
     major minor          age         arrival     airborne time sec    mo da year  hh    mm ss lat
                 ads status                          csa
                    tcas installed                      surfaceIa
                       tcas mode

0020 22 A9 D5 60 E2 EE E7 21 C3 D3 DB 5B 00 FF 7E C1 5F 3A 00 00 00 00 00 00 00 00 54 C3 B8 43 42 2B  
     33 44 55 66 77 88 dd 22 33 44 55 66 77 88 ff 22 33 44 ff 22 33 44 ff 22 33 44 ff 22 33 44 ff 22
                       lon                     speed       track true  hdg deg     PA feet     geom feet

0040 97 43 00 00 00 00 00 00 00 00 33 33 EF 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  
     33 44 ff 22 33 44 ff 22 33 44 ff 22 33 44 ff 22 33 44 ii 22 33 44 bb bb 22 33 44 55 66 77 88 bb
           ac len M    ac wid M    HFOM        crab deg


0060 00 00 00 00 00 00 00 01 00 03 3F 01 00 00 01 00 02 00 00 00 69 00 00 00 05 00 0D 00 04 02 01 01  
     22 33 44 55 66 77 88 bb bb bb ii 22 33 44 bb bb ii 22 33 44 ii 22 33 44 ii 22 33 44 bb bb bb bb
                          airborne             datum             id          addr        trk source
                             shadow               unk                                       Data Link
                                track uncertainty    num report                                Address Qualifier
                                   valid_flags                                                    airborne

0080 00 00 56 3F 00 80 96 3F 01 01 01 00 00 00 08 26 1D 5F DC 25 E2 3F 8F 84 49 A3 56 50 00 C0 F9 71  
     ff 22 33 44 ff 22 33 44 bb bb bb ss 22 bb dd 22 33 44 55 66 77 88 dd 22 33 44 55 66 77 88 ff 22
     state age   ID Age      air cap           lat                     lon                     closure(M/sec)
                                csa cap
                                   surfIA cap
                                      surfIA prio
        			      	    pad(unknown)

00A0 8D 42 AB 27 49 45 AB 67 4F 45 41 0F 32 45 59 2D 65 43 87 0A 94 43 6C D2 EC 41 DD 75 12 43 B3 36  
     33 44 ff 22 33 44 ff 22 33 44 ff 22 33 44 ff 22 33 44 ff 22 33 44 ff 22 33 44 ff 22 33 44 ff 22
           press alt   geom alt    rel alt     rel dir     true deg distance NM    rel brg     GS kts

00C0 1F 43 00 00 0F C3 00 00 8C 42 00 00 20 C4 9B 36 1F 43 7E 0A 94 43 00 00 00 00 00 00 00 00 01 01  
     33 44 ff 22 33 44 ff 22 33 44 ff 22 33 44 ff 22 33 44 ff 22 33 44 ff 22 33 44 ff 22 33 44 bb bb
           EW kts      NS kts      FPM         rel kts     rel deg     cpa NM      cpa Sec     rel alt src
                                                                                                  true dir datum
 
00E0 01 02 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 54 56 4F 49 34 34 33 20 00 00 00 00 00 00  
     bb bb bb bb bb bb bb bb bb bb ff 22 33 44 ff 22 33 44 aa 22 33 44 55 66 77 88 aa 22 33 44 55 66 
     range src   Emitter Cat    is_tisb                    Callsign                Flt Plan ID
        VV Src      Emerg Pri      AC Len M    AC Wid M   
           VV Dir      CSA Alert
              AlertStat   trafficIa Stat
                             corrrelation status
0100 00 00 CF 1B 00 00 68 00 00 00 44 43 A6 00 04 02 01 01 00 C4 B5 41 00 90 B3 40 01 01 01 01 00 00  
     77 88 ii 22 33 44             ii 22 33 44
           Valid Flag  ID          Address.....................


Ground Station Log:
As before, request the file(/RAM/GROUND_STATION_LOG), re-inflate it:
(counting from 1)
Byte 1: Count of stations.
Byte 2-5: ?
Per station:(starting at 6 for the first)
Byte 1-4: Site
Byte 5-13: Lat(double, radians)
Byte 14-22: Lon(double, radians)
Byte 23-26: Count
Byte 27-30: Different Count

Weather:
All weather data follows the same general format. Request the file, get the result and then de-segment it:
First int is the decoded size of the data.
Second int is the number of segments.
For each segment a pair of ints, offset into the file, and the size of the segment.
Segment 0 is some meta data, remaining segments are the actual data grouped by type. For instance
NOTAMS may have one segment with locations, one with geometries and one with text data.
The segments >0 all appear to be compressed, look for the usual magic number and re-inflate them.

The current prototype code breaks the data into segments and decompresses but does no further decoding.
The following data types are known:

/RAM/REG_NEXRAD
/RAM/CONUS_NEXRAD
/RAM/SUA
/RAM/W_T_ALOFT
/RAM/AIRMET
/RAM/SIGMET
/RAM/METAR
/RAM/GRPH_METAR
/RAM/NOTAM
/RAM/PIREP
/RAM/TAF
