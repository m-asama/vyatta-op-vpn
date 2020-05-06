#!/usr/bin/perl
#
# Module Vyatta::VPN::OpMode.pm
#
# **** License ****
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2008 Vyatta, Inc.
# All Rights Reserved.
#
# Author: John Southworth
# Date: January 2011
# Description: Script to execute op-mode commands for IPSEC VPN
#
# **** End License ****
#

package Vyatta::VPN::OPMode;

use lib "/opt/vyatta/share/perl5/";
use Vyatta::VPN::Util;
use Vyatta::Config;
use Net::IP;
use strict;

sub conv_id {
  my $peer = pop(@_);
  my $netipobj = new Net::IP ($peer);
  if (defined $netipobj and $netipobj->size() == 1) {
    $peer = $peer;
  } elsif ($peer =~ /\%any/) { # XXX: ???
    $peer = "any";
  } else {
    $peer = "\@$peer";
  }
  return $peer;
}

sub conv_dh_group {
  my $dhgrp = pop(@_);
  my $dh_group = '';
  if ($dhgrp eq "MODP_768"){
    $dh_group = 1;
  } elsif ($dhgrp eq "MODP_1024"){
    $dh_group = 2;
  } elsif ($dhgrp eq "MODP_1536"){
    $dh_group = 5;
  } elsif ($dhgrp eq "MODP_2048"){
    $dh_group = 14;
  } elsif ($dhgrp eq "MODP_3072"){
    $dh_group = 15;
  } elsif ($dhgrp eq "MODP_4096"){
    $dh_group = 16;
  } elsif ($dhgrp eq "MODP_6144"){
    $dh_group = 17;
  } elsif ($dhgrp eq "MODP_8192"){
    $dh_group = 18;
  } elsif ($dhgrp eq "ECP_256"){
    $dh_group = 19;
  } elsif ($dhgrp eq "ECP_384"){
    $dh_group = 20;
  } elsif ($dhgrp eq "ECP_521"){
    $dh_group = 21;
  } elsif ($dhgrp eq "MODP_1024_160"){
    $dh_group = 22;
  } elsif ($dhgrp eq "MODP_2048_224"){
    $dh_group = 23;
  } elsif ($dhgrp eq "MODP_2048_256"){
    $dh_group = 24;
  } elsif ($dhgrp eq "ECP_192"){
    $dh_group = 25;
  } elsif ($dhgrp eq "ECP_224"){
    $dh_group = 26;
  } elsif ($dhgrp eq "<N/A>"){
    $dh_group = "n/a";
  } else {
    $dh_group = $dhgrp;
  }
  return $dh_group;
}

sub conv_hash {
  my $hash = pop(@_);
  if ($hash eq "HMAC_SHA1_96") {
    $hash = "sha1";
  } elsif ($hash eq "HMAC_SHA1_160") {
    $hash = "sha1_160";
  } elsif ($hash eq "HMAC_SHA2_256_128") {
    $hash = "sha256";
  } elsif ($hash eq "HMAC_SHA2_256_96") {
    $hash = "sha256_96";
  } elsif ($hash eq "HMAC_SHA2_384_192") {
    $hash = "sha384";
  } elsif ($hash eq "HMAC_SHA2_512_256") {
    $hash = "sha512";
  } elsif ($hash eq "HMAC_MD5_96") {
    $hash = "md5";
  } elsif ($hash eq "HMAC_MD5_128") {
    $hash = "md5_128";
  }
  return $hash;
}

sub conv_enc {
  my $enc = pop(@_);
  if ($enc eq "3DES") {
    $enc = "3des";
  } elsif ($enc eq "AES_CBC-128") {
    $enc = "aes128";
  } elsif ($enc eq "AES_CBC-192") {
    $enc = "aes192";
  } elsif ($enc eq "AES_CBC-256") {
    $enc = "aes256";
  }
  return $enc;
}

sub conv_natt {
  my $natt = pop(@_);
  if ($natt == 0){
    $natt = "no";
  } else {
    $natt = "yes";
  }
  return $natt;
}

sub conv_id_rev
{
  my $peerid = pop(@_);
  if ($peerid =~ /@(.*)/){
     $peerid = $1;
  }
  return $peerid;
}
sub conv_bytes {
   my $bytes = pop(@_);
   my $suffix = '';
   $bytes =~ s/\s+$//;
   if ($bytes > 1024 && $bytes < 1048576){
     $bytes = $bytes/1024;
     $suffix = "K";
   } elsif ($bytes >= 1048576 && $bytes < 1073741824){
     $bytes = $bytes/1048576;
     $suffix = "M";
   } elsif ($bytes >= 1073741824){
     $bytes = $bytes/1073741824;
     $suffix = "G";
   }
   $bytes = sprintf("%.1f",$bytes);
   $bytes = "$bytes$suffix";
}
sub conv_ip{
  my $peerip = pop(@_);
  if ($peerip =~ /\@.*/){
    $peerip = "0.0.0.0";
  } elsif ($peerip =~ /\%any/){
    $peerip = "0.0.0.0";
  }
  return $peerip;
}
sub nat_detect {
  (my $lip, my $rip) = @_;
  my @values;
  if ($lip =~ /(\d+\.\d+\.\d+\.\d+):(\d+)/){
    push (@values, $1);
    push (@values, 1);
    push (@values, $2);
  } else {
    push (@values, $lip);
    push (@values, 0);
    push (@values, 'n/a');
  }
  if ($rip =~ /(\d+\.\d+\.\d+\.\d+):(\d+)/){
    push (@values, $1);
    push (@values, $2);
  } else {
    push (@values, $rip);
    push (@values, 'n/a');
  }
  return @values;
}

sub get_tunnel_info {
  #my $cmd = "cat /home/vyatta/test.txt";
  #my $cmd = "sudo ipsec statusall";
  my $cmd = "sudo swanctl -l";
  open(my $IPSECSTATUS, ,'-|', $cmd);
  my @ipsecstatus = [];
  while(<$IPSECSTATUS>){
    push (@ipsecstatus, $_);
  }
  process_tunnels(\@ipsecstatus);
}

sub get_tunnel_info_peer {
  my $peer = pop(@_);
  #my $cmd = "cat /home/vyatta/test.txt | grep peer-$peer";
  #my $cmd = "sudo ipsec statusall | grep peer-$peer-";
  my $cmd = "sudo swanctl -l";
  open(my $IPSECSTATUS, ,'-|', $cmd);
  my @ipsecstatus = [];
  while(<$IPSECSTATUS>){
    push (@ipsecstatus, $_);
  }
  my %tunnel_hash = process_tunnels(\@ipsecstatus);
  my @delkeys = ();
  foreach my $key (keys %tunnel_hash) {
    push (@delkeys, $key) if $key !~ m/^peer-$peer-/;
  }
  foreach my $key (@delkeys) {
    delete $tunnel_hash{$key};
  }
  return %tunnel_hash
}

# set vpn ipsec site-to-site peer 172.16.1.1 ike-group IKE-G
# set vpn ipsec ike-group IKE-G lifetime 28800
sub get_ikelife {
  my $tunnelnum = pop(@_);
  my $peerid = pop(@_);
  my $ikelife = 28800;
  my $cfg = new Vyatta::Config();
  my $ikeg = $cfg->returnOrigValue("vpn ipsec site-to-site peer $peerid ike-group");
  if (not defined $ikeg) {
    return $ikelife;
  }
  my $ikel = $cfg->returnOrigValue("vpn ipsec ike-group $ikeg lifetime");
  if (not defined $ikel) {
    return $ikelife;
  }
  return $ikel;
}

# set vpn ipsec site-to-site peer 172.16.1.1 default-esp-group ESP-G
# set vpn ipsec site-to-site peer 172.16.1.1 tunnel 1 esp-group ESP-G
# set vpn ipsec site-to-site peer 172.16.1.1 vti esp-group ESP-G
# set vpn ipsec esp-group ESP-G lifetime 3600
sub get_lifetime {
  my $tunnelnum = pop(@_);
  my $peerid = pop(@_);
  my $lifetime = 3600;
  my $cfg = new Vyatta::Config();
  my $espg;
  if ($tunnelnum eq 'vti') {
    $espg = $cfg->returnOrigValue("vpn ipsec site-to-site peer $peerid vti esp-group");
  } else {
    $espg = $cfg->returnOrigValue("vpn ipsec site-to-site peer $peerid tunnel $tunnelnum esp-group");
  }
  if (not defined $espg) {
    $espg = $cfg->returnOrigValue("vpn ipsec site-to-site peer $peerid default-esp-group");
  }
  if (not defined $espg) {
    return $lifetime;
  }
  my $espl = $cfg->returnOrigValue("vpn ipsec esp-group $espg lifetime");
  if (not defined $espl) {
    return $lifetime;
  }
  return $espl;
}

sub process_tunnels{
  my @ipsecstatus = @{pop(@_)};
  my %tunnel_hash = ();
  my %esp_hash = ();
  my ($connectid, $peerid, $tunnelnum, $ikever);
  my ($lid, $lip, $rid, $rip, $natt, $natsrc, $natdst);
  my ($ikeencrypt, $ikehash, $dhgrp, $ikeatime, $ikestate);
  my ($encryption, $hash, $pfsgrp, $atime, $state);
  my ($inbytes, $inlastused, $outbytes, $outlastused, $lsnet, $rsnet);
  my ($inspi, $outspi, $ikelife, $lifetime);
  foreach my $line (@ipsecstatus) {
    # peer-0.0.0.0-tunnel-10: #2, ESTABLISHED, IKEv1, 1f733a56158a5775_i 6e63432b3eff26f0_r*
    # peer-0.0.0.0-tunnel-10: #1, ESTABLISHED, IKEv2, 7fb80eb8b105d255_i dc54996ef4f1fc1b_r*
    # peer-172.16.1.1-tunnel-vti: #5, ESTABLISHED, IKEv1, 6634b929ca9b23d3_i* af764cc626ec7ef4_r
    # peer-172.16.1.1-tunnel-vti: #1, ESTABLISHED, IKEv2, 52e612a6d30e65c6_i* 1d86f9864dff6836_r
    if ($line =~ m/^\S+: #/) {
      $connectid = undef; $peerid = undef; $tunnelnum = undef; $ikever = 'n/a';
      $lid = 'n/a'; $lip = 'n/a'; $rid = 'n/a'; $rip = 'n/a'; $natt = 0; $natsrc = 'n/a'; $natdst = 'n/a';
      $ikeencrypt = 'n/a'; $ikehash = 'n/a'; $dhgrp = 'n/a'; $ikeatime = 'n/a'; $ikestate = 'down';
      $encryption = 'n/a'; $hash = 'n/a'; $pfsgrp = 'n/a'; $atime = 'n/a'; $state = 'down';
      $inbytes = 'n/a'; $inlastused = 3600; $outbytes = 'n/a'; $outlastused = 3600; $lsnet = 'n/a'; $rsnet = 'n/a';
      $inspi = 'n/a'; $outspi = 'n/a'; $ikelife = 'n/a'; $lifetime = 'n/a';
    }
    if ($line =~ m/^(peer-(.*)-tunnel-(.*)): #.*, ESTABLISHED, (IKEv(1|2))/) {
      $connectid = $1;
      $peerid = $2;
      $tunnelnum = $3;
      $ikever = $4;
      $ikelife = get_ikelife($peerid, $tunnelnum);
      $lifetime = get_lifetime($peerid, $tunnelnum);
      $peerid = conv_id($peerid);
    }
    #   local  '172.16.2.1' @ 172.16.2.1[4500]
    if ($line =~ m/^  local  '([^']+)' \@ ([^\[]+)\[([^\]]+)\]/) {
      $lid = conv_id($1);
      $lip = $2;
      $natsrc = $3;
    }
    #   remote '172.16.1.1' @ 172.16.1.1[4500]
    if ($line =~ m/^  remote '([^']+)' \@ ([^\[]+)\[([^\]]+)\]/) {
      $rid = conv_id($1);
      $rip = $2;
      $natdst = $3;
    }
    #   AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_1024
    if ($line =~ m/^  [^\/\s]+\/[^\/\s]+\/[^\/\s]+/) {
      $line =~ s/\/PPK//;
      if ($line =~ m/^  ([^\/\s]+)(\/([^\/\s]+))?\/([^\/\s]+)\/([^\/\s]+)/) {
        $ikeencrypt = conv_enc($1);
        $ikehash = conv_hash($3);
        $dhgrp = conv_dh_group($5);
      }
    }
    #   established 5s ago, rekeying in 28141s
    if ($line =~ m/^  established (\d+)s ago/) {
      $ikeatime = $1;
      $ikestate = 'up';
      if (defined $connectid
        and (not exists $tunnel_hash{$connectid}
          or ($tunnel_hash{$connectid}->{_ikestate} ne $ikestate)
          or ($tunnel_hash{$connectid}->{_inlastused} > $inlastused)
          or ($tunnel_hash{$connectid}->{_outlastused} > $outlastused))) {
        $tunnel_hash{$connectid} = {
                  _peerid      => $peerid,
                  _tunnelnum   => $tunnelnum,
                  _ikever      => $ikever,
                  _lip         => $lip,
                  _rip         => $rip,
                  _lid         => $lid,
                  _rid         => $rid,
                  _lsnet       => $lsnet,
                  _rsnet       => $rsnet,
                  _lproto      => 'all',
                  _rproto      => 'all',
                  _lport       => 'all',
                  _rport       => 'all',
                  _lca         => undef,
                  _rca         => undef,
                  _newestspi   => 'n/a',
                  _newestike   => 'n/a',
                  _encryption  => $encryption,
                  _hash        => $hash,
                  _inspi       => $inspi,
                  _outspi      => $outspi,
                  _pfsgrp      => $pfsgrp,
                  _ikeencrypt  => $ikeencrypt,
                  _ikehash     => $ikehash,
                  _natt        => $natt,
                  _natsrc      => $natsrc,
                  _natdst      => $natdst,
                  _ikestate    => $ikestate,
                  _dhgrp       => $dhgrp,
                  _state       => $state,
                  _inbytes     => $inbytes,
                  _inlastused  => $inlastused,
                  _outbytes    => $outbytes,
                  _outlastused => $outlastused,
                  _ikelife     => $ikelife,
                  _ikeatime    => $ikeatime,
                  _ikeexpire   => 'n/a',
                  _lifetime    => $lifetime,
                  _atime       => $atime,
                  _expire      => 'n/a' };
      }
    }
    #   peer-172.16.1.1-tunnel-10: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128/MODP_1024
    #   peer-172.16.1.1-tunnel-11: #2, reqid 2, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128/MODP_1024
    #   peer-172.16.1.1-tunnel-10: #3, reqid 1, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128
    #   peer-172.16.1.1-tunnel-vti: #5, reqid 3, REKEYED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128/MODP_1024
    #   peer-172.16.1.1-tunnel-vti: #6, reqid 3, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128/MODP_1024
    #   peer-0.0.0.0-tunnel-10: #1, reqid 1, INSTALLED, TUNNEL-in-UDP, ESP:AES_CBC-256/HMAC_SHA2_256_128/MODP_1024
    if ($line =~ m/^  (\S+): #/) {
      $connectid = undef; $peerid = undef; $tunnelnum = undef;
      if ($1 !~ m/peer-.*-tunnel-.*/) {
        $ikever = 'n/a';
        $lid = 'n/a'; $lip = 'n/a'; $rid = 'n/a'; $rip = 'n/a'; $natt = 0; $natsrc = 'n/a'; $natdst = 'n/a';
        $ikeencrypt = 'n/a'; $ikehash = 'n/a'; $dhgrp = 'n/a'; $ikeatime = 'n/a'; $ikestate = 'down';
      }
      $natt = 0;
      $encryption = 'n/a'; $hash = 'n/a'; $pfsgrp = 'n/a'; $atime = 'n/a'; $state = 'down';
      $inbytes = 'n/a'; $inlastused = 3600; $outbytes = 'n/a'; $outlastused = 3600; $lsnet = 'n/a'; $rsnet = 'n/a';
      $inspi = 'n/a'; $outspi = 'n/a'; $ikelife = 'n/a'; $lifetime = 'n/a';
    }
    if ($line =~ m/^  (peer-(.*)-tunnel-(.*)): #.*, INSTALLED, (TUNNEL(-in-UDP)?), ESP:(.+)/) {
      $connectid = $1;
      $peerid = $2;
      $tunnelnum = $3;
      $ikelife = get_ikelife($peerid, $tunnelnum);
      $lifetime = get_lifetime($peerid, $tunnelnum);
      $peerid = conv_id($peerid);
      if ($4 eq 'TUNNEL-in-UDP') {
        $natt = 1;
      }
      my $algs = $6;
      $algs =~ s/\/ESN//;
      if ($algs =~ m/^([^\/\s]+)\/([^\/\s]+)(\/([^\/\s]+))?/) {
        $encryption = conv_enc($1);
        $hash = conv_hash($2);
        $pfsgrp = conv_dh_group($4);
      }
    }
    #     installed 72s ago, rekeying in 2554s, expires in 3528s
    #     installed 8s ago
    if ($line =~ m/^    installed (\d+)s ago/) {
      $atime = $1;
      $state = 'up';
    }
    #     in  c7a5807e,      0 bytes,     0 packets
    #     in  cf6340f7,    588 bytes,     7 packets,     0s ago
    if ($line =~ m/^    in  ([0-9a-f]+)?.*,\s+(\d+) bytes,\s+(\d+) packets(,\s+(\d+)s ago)?/) {
      $inspi = $1;
      $inbytes = $2;
      $inlastused = $5 if defined $5;
    }
    #     out c1f127f5,      0 bytes,     0 packets
    #     out cbd9e925,    588 bytes,     7 packets,     0s ago
    if ($line =~ m/^    out ([0-9a-f]+)?.*,\s+(\d+) bytes,\s+(\d+) packets(,\s+(\d+)s ago)?/) {
      $outspi = $1;
      $outbytes = $2;
      $outlastused = $5 if defined $5;
    }
    #     local  192.168.22.0/24
    if ($line =~ m/^    local  (\S+)/) {
      $lsnet = $1;
    }
    #     remote 192.168.2.0/24
    if ($line =~ m/^    remote (\S+)/) {
      $rsnet = $1;
      if (defined $connectid
        and (not exists $tunnel_hash{$connectid}
          or ($tunnel_hash{$connectid}->{_state} ne $state)
          or ($tunnel_hash{$connectid}->{_inlastused} > $inlastused)
          or ($tunnel_hash{$connectid}->{_outlastused} > $outlastused))) {
        $tunnel_hash{$connectid} = {
                  _peerid      => $peerid,
                  _tunnelnum   => $tunnelnum,
                  _ikever      => $ikever,
                  _lip         => $lip,
                  _rip         => $rip,
                  _lid         => $lid,
                  _rid         => $rid,
                  _lsnet       => $lsnet,
                  _rsnet       => $rsnet,
                  _lproto      => 'all',
                  _rproto      => 'all',
                  _lport       => 'all',
                  _rport       => 'all',
                  _lca         => undef,
                  _rca         => undef,
                  _newestspi   => 'n/a',
                  _newestike   => 'n/a',
                  _encryption  => $encryption,
                  _hash        => $hash,
                  _inspi       => $inspi,
                  _outspi      => $outspi,
                  _pfsgrp      => $pfsgrp,
                  _ikeencrypt  => $ikeencrypt,
                  _ikehash     => $ikehash,
                  _natt        => $natt,
                  _natsrc      => $natsrc,
                  _natdst      => $natdst,
                  _ikestate    => $ikestate,
                  _dhgrp       => $dhgrp,
                  _state       => $state,
                  _inbytes     => $inbytes,
                  _inlastused  => $inlastused,
                  _outbytes    => $outbytes,
                  _outlastused => $outlastused,
                  _ikelife     => $ikelife,
                  _ikeatime    => $ikeatime,
                  _ikeexpire   => 'n/a',
                  _lifetime    => $lifetime,
                  _atime       => $atime,
                  _expire      => 'n/a' };
      }
    }
  }

  # Cleanse esp_hash
#  foreach my $connectid (keys %esp_hash) {
#    foreach my $esp_sa (keys %{$esp_hash{$connectid}}) {
#      delete $esp_hash{$connectid}{$esp_sa} if (not defined($esp_hash{$connectid}{$esp_sa}{last_used}));
#    }
#  }

  # For each tunnel, loop through all ESP SA's and extract data from one most recently used
#  foreach my $connectid (keys %esp_hash) {
#    foreach my $esp_sa (reverse sort {$esp_hash{$a}{last_used} <=> $esp_hash{$b}{last_used}} keys %{$esp_hash{$connectid}}) {
#      foreach my $data (keys %{$esp_hash{$connectid}{$esp_sa}}) {
#        $tunnel_hash{$connectid}->{$data} = $esp_hash{$connectid}{$esp_sa}{$data} if ($data =~ /^_/);
#      }
#      my $atime = $tunnel_hash{$connectid}->{_lifetime} - $tunnel_hash{$connectid}->{_expire};
#      $tunnel_hash{$connectid}->{_state} = "up" if ($atime >= 0);
#      last;
#    }
#  }

  my $cmd = "sudo cat /etc/ipsec.conf";
  open(my $IPSECCONF, '-|', $cmd);
  my @ipsecconf = [];
  while(<$IPSECCONF>){
    push (@ipsecconf, $_);
  }
  for my $line (@ipsecconf) {
    chomp($line);
    if ($line =~ m/^conn (peer-(.*)-tunnel-(.*))/) {
      $connectid = $1;
      $peerid = $2;
      $tunnelnum = $3;
      $peerid = conv_id($peerid);
      $ikever = 'n/a';
      $lip = 'n/a';
      $rip = 'n/a';
      $lid = 'n/a';
      $rid = 'n/a';
      $lsnet = 'n/a';
      $rsnet = 'n/a';
    }
    if ($line =~ m/\skeyexchange=(.*)/) {
      $ikever = $1;
      $ikever =~ s/ike/IKE/;
    }
    if ($line =~ m/\sleft=(.*)/) {
      $lip = $1;
    }
    if ($line =~ m/\sright=(.*)/) {
      $rip = $1;
    }
    if ($line =~ m/\sleftid=(.*)/) {
      $lid = $1;
      $lid =~ s/^\"//;
      $lid =~ s/\"$//;
    }
    if ($line =~ m/\srightid=(.*)/) {
      $rid = $1;
      $rid =~ s/^\"//;
      $rid =~ s/\"$//;
    }
    if ($line =~ m/\sleftsubnet=(.*)/) {
      $lsnet = $1;
    }
    if ($line =~ m/\srightsubnet=(.*)/) {
      $rsnet = $1;
    }
    if ($line =~ m/^#conn $connectid$/) {
      if (not exists $tunnel_hash{$connectid}) {
        $tunnel_hash{$connectid} = {
                  _peerid      => $peerid,
                  _tunnelnum   => $tunnelnum,
                  _ikever      => $ikever,
                  _lip         => $lip,
                  _rip         => $rip,
                  _lid         => $lid,
                  _rid         => $rid,
                  _lsnet       => $lsnet,
                  _rsnet       => $rsnet,
                  _lproto      => 'all',
                  _rproto      => 'all',
                  _lport       => 'all',
                  _rport       => 'all',
                  _lca         => undef,
                  _rca         => undef,
                  _newestspi   => 'n/a',
                  _newestike   => 'n/a',
                  _encryption  => 'n/a',
                  _hash        => 'n/a',
                  _inspi       => 'n/a',
                  _outspi      => 'n/a',
                  _pfsgrp      => 'n/a',
                  _ikeencrypt  => 'n/a',
                  _ikehash     => 'n/a',
                  _natt        => 'n/a',
                  _natsrc      => 'n/a',
                  _natdst      => 'n/a',
                  _ikestate    => 'down',
                  _dhgrp       => 'n/a',
                  _state       => 'down',
                  _inbytes     => 'n/a',
                  _inlastused  => 3600,
                  _outbytes    => 'n/a',
                  _outlastused => 3600,
                  _ikelife     => 'n/a',
                  _ikeatime    => 'n/a',
                  _ikeexpire   => 'n/a',
                  _lifetime    => 'n/a',
                  _atime       => 'n/a',
                  _expire      => 'n/a' };
      }
    }
  }

  return %tunnel_hash;
}

sub conv_time {
  my @time = split(/\s+/, $_[0]);
  my ($rc, $multiply) = ("", 1);

  if ($time[0] eq 'disabled') {
    $rc = 0;
  } else {
    
    if ($time[2] =~ /minute/i) {
      $multiply = 60;
    } elsif ($time[2] =~ /hour/i) {
      $multiply = 3600;
    } elsif ($time[2] =~ /day/i) {
      $multiply = 86400;
    }

    $rc = $time[1] * $multiply;
  }
  
  return $rc;
}

sub get_conns
{
  my $cmd = "sudo cat /etc/ipsec.conf";
  open(my $IPSECCONF, '-|', $cmd);
  my @ipsecconf = [];
  while(<$IPSECCONF>){
    push (@ipsecconf, $_);
  }
  my %th = ();
  for my $line (@ipsecconf){
    next if ($line =~/^\#/);
    if ($line =~ /peer-(.*?)-tunnel-(.*)/){
      my $peer = $1;
      my $tun = $2;
      if (not exists $th{$peer}){
        $th{$peer} = { _conns => [$tun],
                       _peerid => conv_id($peer)
                     };
      } else {
        push (@{$th{$peer}->{_conns}}, $tun);
      }
    }
  }
  return %th;
}
sub get_peers_for_cli
{
    my %tunnel_hash = get_conns();
    for my $peer (peerSort( keys %tunnel_hash )) {
      print $tunnel_hash{$peer}->{_peerid}."\n";
    }
}

sub get_conn_for_cli
{
    my $peerid = pop(@_);
    my %th = get_conns();
    for my $peer (peerSort( keys %th )) {
      next if (not ($th{$peer}->{_peerid} eq $peerid));
      for my $conn ( @{$th{$peer}->{_conns}} ){
        print "$conn\n";
      }
    }
}

sub peerSort {
  map { $_ -> [0] }
    sort {
      our @a = split(/\./, $a->[1]);
      our @b = split(/\./, $b->[1]);
      $a[0] <=> $b[0] or
      $a[1] <=> $b[1] or 
      $a[2] <=> $b[2] or
      $a[3] <=> $b[3];
    } map { my $tmp = (split (/-/,$_))[0]; 
            if ($tmp =~ /@(.*)/){
              my @tmp = split('', $1);
              my $int1 = ord(uc($tmp[0]))*256;
              my $int2 = ord(uc($tmp[1]))*256;
              my $int3 = ord(uc($tmp[2]))*256;
              my $int4 = ord(uc($tmp[3]))*256;
              $tmp = "$int1.$int2.$int3.$int4";
            }
            [ $_, $tmp ]
      }
  @_;
}

sub tunSort {
  sort { 
    $a->[0] <=> $b->[0];
  } @_;
}

sub show_ipsec_sa
{
    my %tunnel_hash = get_tunnel_info();
    display_ipsec_sa_brief(\%tunnel_hash);
}
sub show_ipsec_sa_detail
{
    my %tunnel_hash = get_tunnel_info();
    display_ipsec_sa_detail(\%tunnel_hash);
}

sub show_ipsec_sa_peer
{
    my $peerid = pop(@_);
    my %tunnel_hash = get_tunnel_info_peer($peerid);
    display_ipsec_sa_brief(\%tunnel_hash);
}

sub show_ipsec_sa_stats_peer
{
    my $peerid = pop(@_);
    my %tunnel_hash = get_tunnel_info_peer($peerid);
    display_ipsec_sa_stats(\%tunnel_hash);
}

sub show_ipsec_sa_stats_conn
{
    my %tmphash = ();
    (my $peerid, my $tun) = @_;
    my %th = get_tunnel_info_peer($peerid);
    for my $peer ( keys %th ) {
      if ($th{$peer}->{_tunnelnum} eq $tun){
        $tmphash{$peer} = \%{$th{$peer}};
      }
    }
    display_ipsec_sa_stats(\%tmphash);
}

sub show_ipsec_sa_peer_detail
{
    my $peerid = pop(@_);
    my %tunnel_hash = get_tunnel_info_peer($peerid);
    display_ipsec_sa_detail(\%tunnel_hash);
}

sub show_ipsec_sa_conn_detail
{
    my %tmphash = ();
    (my $peerid, my $tun) = @_;
    my %th = get_tunnel_info_peer($peerid);
    for my $peer ( keys %th ) {
      if ($th{$peer}->{_tunnelnum} eq $tun){
        $tmphash{$peer} = \%{$th{$peer}};
      }
    }
    display_ipsec_sa_detail(\%tmphash);
}

sub show_ipsec_sa_conn
{
    my %tmphash = ();
    (my $peerid, my $tun) = @_;
    my %th = get_tunnel_info_peer($peerid);
    for my $peer ( keys %th ) {
      if ($th{$peer}->{_tunnelnum} eq $tun){
        $tmphash{$peer} = \%{$th{$peer}};
      }
    }
    display_ipsec_sa_brief(\%tmphash);
}

sub get_connection_status
{
    (my $peerid, my $tun) = @_;
    my %th = get_tunnel_info_peer($peerid);
    for my $peer ( keys %th ) {
      if ($th{$peer}->{_tunnelnum} eq $tun){
        return $th{$peer}->{_state};
      }
    }
}
sub get_peer_ike_status
{
    my ($peerid) = @_;
    my %th = get_tunnel_info_peer($peerid);
    for my $peer ( keys %th ) {
      if ($th{$peer}->{_ikestate} eq 'up'){
        return 'up';    
      }
      if ($th{$peer}->{_ikestate} eq 'init'){
        return 'init';    
      }
    }
    return 'down';
}

sub show_ipsec_sa_natt
{
    my %tunnel_hash = get_tunnel_info();
    my %tmphash = ();
    for my $peer ( keys %tunnel_hash ) {
       if ($tunnel_hash{$peer}->{_natt} == 1 ){
         $tmphash{$peer} = $tunnel_hash{$peer};
       }
    }
    display_ipsec_sa_brief(\%tmphash);
}
sub show_ike_status{
  my $process_id = `sudo cat /var/run/charon.pid`;
  chomp $process_id;

  print <<EOS;
IKE Process Running 

PID: $process_id

EOS
  exit 0;
}

sub show_ike_sa
{
    my %tunnel_hash = get_tunnel_info();
    display_ike_sa_brief(\%tunnel_hash);
}

sub show_ipsec_sa_stats
{
     my %tunnel_hash = get_tunnel_info();
     display_ipsec_sa_stats(\%tunnel_hash);
}

sub show_ike_sa_peer
{
    my $peerid = pop(@_);
    my %tunnel_hash = get_tunnel_info_peer($peerid);
    display_ike_sa_brief(\%tunnel_hash);
}

sub show_ike_sa_natt
{
    my %tunnel_hash = get_tunnel_info();
    my %tmphash = ();
    for my $peer ( keys %tunnel_hash ) {
      if ($tunnel_hash{$peer}->{_natt} == 1 ){
        $tmphash{$peer} = $tunnel_hash{$peer};
      }
    }
    display_ike_sa_brief(\%tmphash);
}

sub show_ike_secrets
{
    my $secret_file = '/etc/ipsec.secrets';
    unless ( -r $secret_file) {
      die "No secrets file $secret_file\n";
    }   
    open(my $DAT, '<', $secret_file);
    my @raw_data=<$DAT>;
    close($DAT);
    foreach my $line (@raw_data) {
      if ($line =~ /PSK/) {
        my ($lip, $pip, $lid, $pid, $secret) = ('', '', 'N/A', 'N/A', '');
        ($secret) = $line =~ /.*:\s+PSK\s+(\"\S+\")/;
        ($lip, $pip) = $line =~ /^(\S+)\s+(\S+)\s+\:\s+PSK\s+\"\S+\"/;
         # This processing with depend heavily on the way we write ipsec.secrets
         # lines with 3 entries are tagged by the config module so that we can 
         # tell if the 3rd entry is a localid or peerid (left or right)
        if (! defined($lip)){
          if ($line =~ /^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+\:\s+PSK\s+\"\S+\"/){
            $lip = $1; 
            $pip = $2; 
            $lid = $3; 
            $pid = $4; 
          } elsif ($line =~ 
                   /^(\S+)\s+(\S+)\s+(\S+)\s+\:\s+PSK\s+\"\S+\".*\#(.*)\#/){
            $lip = $1; 
            $pip = $2; 
            if ($4 eq 'RIGHT'){
              $pid = $3
            } else {$lid = $3} 
          }   
        }   
        $lip = '0.0.0.0' if ! defined $lip;
        $pip = '0.0.0.0' if ! defined $pip;
        $pip = '0.0.0.0' if ($pip eq '%any');
        print <<EOH;
Local IP/ID                             Peer IP/ID                           
-----------                             -----------
EOH
        printf "%-39s %-39s\n", $lip, $pip;
        printf "%-39s %-39s\n\n", substr($lid,0,39), substr($pid,0,39);
        print "    Secret: $secret\n";
        print "\n \n";
      }   
    }   
    exit 0;
}

sub display_ipsec_sa_brief
{
    my %th = %{pop(@_)};
    my $listref = [];
    my %tunhash = ();
    my $myid = undef;
    my $peerid = undef;
    my $vpncfg = new Vyatta::Config();
    $vpncfg->setLevel('vpn ipsec site-to-site');
    for my $connectid (keys %th){  
      $peerid = conv_ip($th{$connectid}->{_rip});
      my $lip = conv_ip($th{$connectid}->{_lip});
      my $tunnel = "$peerid-$lip";
      my $peer_configured = conv_id_rev($th{$connectid}->{_peerid});
      if (not exists $tunhash{$tunnel}) {
        $tunhash{$tunnel} = {
          _outspi  => $th{$connectid}->{_outspi},
          _natt  => $th{$connectid}->{_natt},
          _lip  => $lip,
          _peerid => $peer_configured,
          _tunnels => []
        };
      }
      my @tmp = ( $th{$connectid}->{_tunnelnum},
               $th{$connectid}->{_state},
               $th{$connectid}->{_inbytes},
               $th{$connectid}->{_outbytes},
               $th{$connectid}->{_encryption},
               $th{$connectid}->{_hash},
               $th{$connectid}->{_lifetime},
               $th{$connectid}->{_lproto},
               $th{$connectid}->{_expire},
               $th{$connectid}->{_atime});
      push (@{$tunhash{"$tunnel"}->{_tunnels}}, [ @tmp ]);
      
    }
    for my $connid (peerSort (keys %tunhash)){
    print <<EOH;
Peer ID / IP                            Local ID / IP               
------------                            -------------
EOH
      (my $peerid, my $myid) = $connid =~ /(.*?)-(.*)/;
      printf "%-39s %-39s\n", $peerid, $myid;
      my $desc = $vpncfg->returnEffectiveValue("peer $tunhash{$connid}->{_peerid} description");
      print "\n    Description: $desc\n" if (defined($desc));
      print <<EOH;

    Tunnel  State  Bytes Out/In   Encrypt  Hash    NAT-T  A-Time  L-Time  Proto
    ------  -----  -------------  -------  ------  -----  ------  ------  -----
EOH
      for my $tunnel (tunSort(@{$tunhash{$connid}->{_tunnels}})){
        (my $tunnum, my $state, my $inbytes, my $outbytes, 
         my $enc, my $hash, my $life, my $proto, my $expire, my $atime) = @{$tunnel};
        my $lip = $tunhash{$connid}->{_lip};
        my $peerip = conv_ip($peerid);
        my $natt = $tunhash{$connid}->{_natt};
        my $bytesp = 'n/a';
        $enc = conv_enc($enc);
        $hash = conv_hash($hash);
        $natt = conv_natt($natt);
        if (!($inbytes eq 'n/a' && $outbytes eq 'n/a')){
          $outbytes = conv_bytes($outbytes);
          $inbytes = conv_bytes($inbytes);
          $bytesp = "$outbytes/$inbytes";
        }
        printf "    %-7s %-6s %-14s %-8s %-7s %-6s %-7s %-7s %-2s\n",
              $tunnum, $state, $bytesp, $enc, $hash, $natt, 
              $atime, $life, $proto;
      }
    print "\n \n";
    }
}
sub display_ipsec_sa_detail
{
    my %th = %{pop(@_)};
    my $listref = [];
    my %tunhash = ();
    my $myid = undef;
    my $peerid = undef;
    my $vpncfg = new Vyatta::Config();
    $vpncfg->setLevel('vpn ipsec site-to-site');
    for my $connectid (keys %th){  
      my $lip = conv_ip($th{$connectid}->{_lip});
      $peerid = conv_ip($th{$connectid}->{_rip});
      my $tunnel = "$peerid-$lip";
      
      if (not exists $tunhash{$tunnel}) {
        $tunhash{$tunnel} = {
          _peerip      => $th{$connectid}->{_rip},
          _peerid      => $th{$connectid}->{_rid},
          _configpeer  => conv_id_rev($th{$connectid}->{_peerid}),
          _localip     => $th{$connectid}->{_lip},
          _localid     => $th{$connectid}->{_lid},
          _dhgrp       => $th{$connectid}->{_dhgrp},
          _natt        => $th{$connectid}->{_natt},
          _natsrc      => $th{$connectid}->{_natsrc},
          _natdst      => $th{$connectid}->{_natdst},
          _tunnels     => []
        };
      }
      my @tmp = ( $th{$connectid}->{_tunnelnum},
               $th{$connectid}->{_state},
               $th{$connectid}->{_inspi},
               $th{$connectid}->{_outspi},
               $th{$connectid}->{_encryption},
               $th{$connectid}->{_hash},
               $th{$connectid}->{_pfsgrp},
               $th{$connectid}->{_lsnet},
               $th{$connectid}->{_rsnet},
               $th{$connectid}->{_inbytes},
               $th{$connectid}->{_outbytes},
               $th{$connectid}->{_lifetime},
               $th{$connectid}->{_expire},
               $th{$connectid}->{_lca},
               $th{$connectid}->{_rca},
               $th{$connectid}->{_lproto},
               $th{$connectid}->{_rproto},
               $th{$connectid}->{_lport},
               $th{$connectid}->{_rport},
               $th{$connectid}->{_atime});
      push (@{$tunhash{$tunnel}->{_tunnels}}, [ @tmp ]);
    }
    for my $connid (peerSort(keys %tunhash)){
      my $natt = conv_natt($tunhash{$connid}->{_natt});
      my $peerip = conv_ip($tunhash{$connid}->{_peerip});
      my $localid = $tunhash{$connid}->{_localid};
      if ($localid =~ /CN=(.*?),/){
        $localid = $1;
      }
      my $peerid = $tunhash{$connid}->{_peerid};
      if ($peerid =~ /CN=(.*?),/){
        $peerid = $1;
      }
      my $desc = $vpncfg->returnEffectiveValue("peer $tunhash{$connid}->{_configpeer} description");
      print "------------------------------------------------------------------\n";
      print "Peer IP:\t\t$peerip\n";
      print "Peer ID:\t\t$peerid\n";
      print "Local IP:\t\t$tunhash{$connid}->{_localip}\n";
      print "Local ID:\t\t$localid\n";
      print "NAT Traversal:\t\t$natt\n";
      print "NAT Source Port:\t$tunhash{$connid}->{_natsrc}\n";
      print "NAT Dest Port:\t\t$tunhash{$connid}->{_natdst}\n";
      print "\nDescription:\t\t$desc\n" if (defined($desc));
      print "\n";
      for my $tunnel (tunSort(@{$tunhash{$connid}->{_tunnels}})){
        (my $tunnum, my $state, my $inspi, my $outspi, my $enc,
         my $hash, my $pfsgrp, my $srcnet, my $dstnet,
         my $inbytes, my $outbytes, my $life, my $expire, my $lca, 
         my $rca, my $lproto, my $rproto, my $lport, my $rport, my $atime) = @{$tunnel};
        $enc = conv_enc($enc);
        $hash = conv_hash($hash);
        $lport = 'all' if ($lport eq '0');
        $rport = 'all' if ($rport eq '0');
        $pfsgrp = conv_dh_group($pfsgrp);
        
        $inbytes = conv_bytes($inbytes);
        $outbytes = conv_bytes($outbytes);

        print "    Tunnel $tunnum:\n";
        print "        State:\t\t\t$state\n";
        print "        Inbound SPI:\t\t$inspi\n";
        print "        Outbound SPI:\t\t$outspi\n";
        print "        Encryption:\t\t$enc\n";
        print "        Hash:\t\t\t$hash\n";
        print "        PFS Group:\t\t$pfsgrp\n";
        if (defined $lca){
        print "        \n";
          print "        CA:\n";
          foreach my $field (split(', ', $lca)){
            $field=~s/\"//g;
            print "            $field\n";
          }
        }
        #print "        Local CA:\t\t$lca\n" if defined($lca);
        #print "        Right CA:\t\t$rca\n" if defined($rca);
        print "        \n";
        print "        Local Net:\t\t$srcnet\n";
        print "        Local Protocol:\t\t$lproto\n";
        print "        Local Port: \t\t$lport\n";
        print "        \n";
        print "        Remote Net:\t\t$dstnet\n";
        print "        Remote Protocol:\t$rproto\n";
        print "        Remote Port: \t\t$rport\n";
        print "        \n";
        print "        Inbound Bytes:\t\t$inbytes\n";
        print "        Outbound Bytes:\t\t$outbytes\n";
        print "        Active Time (s):\t$atime\n";
        print "        Lifetime (s):\t\t$life\n";
        print "    \n";
      }
      print "\n";
    }
}

sub display_ipsec_sa_stats
{
    my %th = %{pop(@_)};
    my $listref = [];
    my %tunhash = ();
    my $myid = undef;
    my $peerid = undef;
    my $vpncfg = new Vyatta::Config();
    $vpncfg->setLevel('vpn ipsec site-to-site');
    for my $connectid (keys %th){  
      my $lip = conv_ip($th{$connectid}->{_lip});
      $peerid = conv_ip($th{$connectid}->{_rip});
      my $tunnel = "$peerid-$lip";
      
      if (not exists $tunhash{$tunnel}) {
        $tunhash{$tunnel}={
          _configpeer  => conv_id_rev($th{$connectid}->{_peerid}),
          _tunnels     => []
        };
      }
        my @tmp = ( $th{$connectid}->{_tunnelnum},
               $th{$connectid}->{_lsnet},
               $th{$connectid}->{_rsnet},
               $th{$connectid}->{_inbytes},
               $th{$connectid}->{_outbytes} );
        push (@{$tunhash{$tunnel}->{_tunnels}}, [ @tmp ]);
    }
    for my $connid (peerSort(keys %tunhash)){
    print <<EOH;
Peer ID / IP                            Local ID / IP               
------------                            -------------
EOH
      (my $peerid, my $myid) = $connid =~ /(.*?)-(.*)/;
      printf "%-39s %-39s\n", $peerid, $myid;
      my $desc = $vpncfg->returnEffectiveValue("peer $tunhash{$connid}->{_configpeer} description");
      print "\n  Description: $desc\n" if (defined($desc));
      print <<EOH;

  Tunnel Dir Source Network               Destination Network          Bytes
  ------ --- --------------               -------------------          -----
EOH
      for my $tunnel (tunSort(@{$tunhash{$connid}->{_tunnels}})){
        (my $tunnum, my $srcnet, my $dstnet, 
         my $inbytes, my $outbytes) = @{$tunnel};
        printf "  %-6s %-3s %-28s %-28s %-8s\n",
	      $tunnum, 'in', $dstnet, $srcnet, $inbytes;
        printf "  %-6s %-3s %-28s %-28s %-8s\n",
	      $tunnum, 'out', $srcnet, $dstnet, $outbytes;
      }
      print "\n \n";
    }
}

sub display_ike_sa_brief {
    my %th = %{pop(@_)};
    my $listref = [];
    my %tunhash = ();
    my $myid = undef;
    my $peerid = undef;
    my $vpncfg = new Vyatta::Config();
    $vpncfg->setLevel('vpn ipsec site-to-site');
    for my $connectid (keys %th){  
      my $lip = $th{$connectid}->{_lip};
      $peerid = $th{$connectid}->{_rip};
      my $tunnel = "$peerid-$lip";
#      next if ($th{$connectid}->{_ikestate} eq 'down');
      if (not exists $tunhash{$tunnel}) {
        $tunhash{$tunnel}={
          _configpeer => conv_id_rev($th{$connectid}->{_peerid}),
          _tunnels => []
        };
      }
        my @tmp = ( $th{$connectid}->{_tunnelnum},
               $th{$connectid}->{_ikestate},
               $th{$connectid}->{_newestike},
               $th{$connectid}->{_ikeencrypt},
               $th{$connectid}->{_ikehash},
               $th{$connectid}->{_dhgrp},
               $th{$connectid}->{_natt},
               $th{$connectid}->{_ikelife},
               $th{$connectid}->{_ikeexpire},
               $th{$connectid}->{_ikeatime},
               $th{$connectid}->{_ikever});
        if (@{$tunhash{$tunnel}->{_tunnels}} > 0
          and $tunhash{$tunnel}->{_tunnels}->[0]->[9] > $th{$connectid}->{_ikeatime}) {
          pop (@{$tunhash{$tunnel}->{_tunnels}});
        }
        if (@{$tunhash{$tunnel}->{_tunnels}} == 0) {
          push (@{$tunhash{$tunnel}->{_tunnels}}, [ @tmp ]);
        }
    }
    for my $connid (peerSort(keys %tunhash)){
    print <<EOH;
Peer ID / IP                            Local ID / IP               
------------                            -------------
EOH
      (my $peerid, my $myid) = $connid =~ /(.*?)-(.*)/;
      printf "%-39s %-39s\n", $peerid, $myid;
      my $desc = $vpncfg->returnEffectiveValue("peer $tunhash{$connid}->{_configpeer} description");
      print "\n    Description: $desc\n" if (defined($desc));
      print <<EOH;

    State  Version  Encrypt  Hash    D-H Grp  NAT-T  A-Time  L-Time
    -----  -------  -------  ------  -------  -----  ------  ------
EOH
      for my $tunnel (tunSort(@{$tunhash{$connid}->{_tunnels}})){
        (my $tunnum, my $state, my $isakmpnum, my $enc, 
         my $hash, my $dhgrp, my $natt, my $life, my $expire, my $atime, my $ikever) = @{$tunnel};
        $enc = conv_enc($enc);
        $hash = conv_hash($hash);
        $natt = conv_natt($natt);
        $dhgrp = conv_dh_group($dhgrp);
        printf "    %-6s %-8s %-8s %-7s %-8s %-6s %-7s %-7s\n",
               $state, $ikever, $enc, $hash, $dhgrp, $natt, $atime, $life;
      }
      print "\n \n";
    }
}
1;
