# SNMP::Info
#
# Copyright (c) 2003-2012 Max Baker and SNMP::Info Developers
# All rights reserved.
#
# Portions Copyright (c) 2002-2003, Regents of the University of California
# All rights reserved.
#
# See COPYRIGHT at bottom

package SNMP::Info;

use warnings;
use strict;
use Exporter;
use SNMP;
use Carp;
use Scalar::Util ();
use Math::BigInt;
use NetAddr::IP::Lite ':lower';

@SNMP::Info::ISA       = qw/Exporter/;
@SNMP::Info::EXPORT_OK = qw//;

our
    ($VERSION, %FUNCS, %GLOBALS, %MIBS, %MUNGE, $AUTOLOAD, $INIT, $DEBUG, %SPEED_MAP,
     $NOSUCH, $BIGINT, $REPEATERS);

$VERSION = '3.975000';

=head1 NAME

SNMP::Info - OO Interface to Network devices and MIBs through SNMP

=head1 VERSION

SNMP::Info - Version 3.975000

=head1 AUTHOR

SNMP::Info is maintained by team of Open Source authors headed by Eric Miller,
Bill Fenner, Max Baker, Jeroen van Ingen and Oliver Gorwits.

Please visit L<https://github.com/netdisco/snmp-info/> for the most up-to-date
list of developers.

SNMP::Info was originally created at UCSC for the Netdisco project L<http://netdisco.org>
by Max Baker.

=head1 DEVICES SUPPORTED

There are now generic classes for most types of device and so the authors
recommend loading SNMP::Info with AutoSpecify, and then reporting to the mail
list any missing functionality (such as neighbor discovery tables).

=head1 SYNOPSIS

 use SNMP::Info;

 my $info = SNMP::Info->new({
                            # Auto Discover your Device Class (Cisco, Juniper, etc ...)
                            AutoSpecify => 1,
                            Debug       => 1,

                            # The rest is passed to SNMP::Session
                            DestHost    => 'router',
                            Community   => 'public',
                            Version     => 2

                            # Parameter reference for SNMPv3
                            # Version   => 3
                            # SecLevel  => 'authPriv', # authPriv|authNoPriv|noAuthNoPriv
                            # SecName   => 'myuser',
                            # AuthProto => 'MD5',      # MD5|SHA
                            # AuthPass  => 'authp4ss',
                            # PrivProto => 'DES',      # DES|AES
                            # PrivPass  => 'pr1vp4ss',

                            # Rarer options - see https://metacpan.org/pod/SNMP for full list
                            # Timeout => 15 * 1000000, # microseconds
                            # RemotePort => 161
                           });

 my $err = $info->error();
 die $err if defined $err;

 my $name  = $info->name();
 my $class = $info->class();
 print "SNMP::Info is using this device class : $class\n";

=head1 SUPPORT

Please direct all support, help, and bug requests to the snmp-info-users
Mailing List at L<http://lists.sourceforge.net/lists/listinfo/snmp-info-users>.

=head1 DESCRIPTION

SNMP::Info gives an object oriented interface to information obtained through
SNMP.

This module is geared towards network devices.  Subclasses exist for a number
of network devices and common MIBs.

=head1 USAGE

=head2 Constructor

=cut

sub new {
    my $proto     = shift;
    my $class     = ref($proto) || $proto;
    my %args      = (ref $_[0] ? %{ $_[0] } : @_);
    my %sess_args = %args;
    my $new_obj   = {};
    bless $new_obj, $class;

    $new_obj->{class} = $class;

    {
        no strict 'refs';
        $new_obj->{init}    = \${ $class . '::INIT' };
        $new_obj->{mibs}    = \%{ $class . '::MIBS' };
        $new_obj->{globals} = \%{ $class . '::GLOBALS' };
        $new_obj->{funcs}   = \%{ $class . '::FUNCS' };
        $new_obj->{munge}   = \%{ $class . '::MUNGE' };
    }

    if ( defined $args{Debug} ) {
        $new_obj->debug( $args{Debug} );
        delete $sess_args{Debug};
    }
    else {
        $new_obj->debug( defined $DEBUG ? $DEBUG : 0 );
    }

    if ( defined $args{DebugSNMP} ) {
        $SNMP::debugging = $args{DebugSNMP};
        delete $sess_args{DebugSNMP};
    }

    my $auto_specific = 0;
    if ( defined $args{AutoSpecify} ) {
        $auto_specific = $args{AutoSpecify} || 0;
        delete $sess_args{AutoSpecify};
    }

    if ( defined $args{BulkRepeaters} ) {
        $new_obj->{BulkRepeaters} = $args{BulkRepeaters};
        delete $sess_args{BulkRepeaters};
    }

    if ( defined $args{BulkWalk} ) {
        $new_obj->{BulkWalk} = $args{BulkWalk};
        delete $sess_args{BulkWalk};
    }

    if ( defined $args{LoopDetect} ) {
        $new_obj->{LoopDetect} = $args{LoopDetect};
        delete $sess_args{LoopDetect};
    }

    if ( defined $args{IgnoreNetSNMPConf} ) {
        $new_obj->{IgnoreNetSNMPConf} = $args{IgnoreNetSNMPConf} || 0;
        delete $sess_args{IgnoreNetSNMPConf};
    }

    if ( defined $args{Offline} ) {
        $new_obj->{Offline} = $args{Offline} || 0;
        delete $sess_args{Offline};
    }

    if ( defined $args{Cache} and ref {} eq ref $args{Cache} ) {
        $new_obj->{$_} = $args{Cache}->{$_} for keys %{$args{Cache}};
        delete $sess_args{Cache};
    }

    my $sess = undef;
    if ( defined $args{Session} ) {
        $sess = $args{Session};
        delete $sess_args{Session};
    }
    if ( defined $args{BigInt} ) {
        $BIGINT = $args{BigInt};
        delete $sess_args{BigInt};
    }
    if ( defined $args{MibDirs} ) {
        $new_obj->{mibdirs} = $args{MibDirs};
        delete $sess_args{MibDirs};
    }

    if ( defined $sess_args{DestHost} ) {
        $sess_args{DestHost} = resolve_desthost($sess_args{DestHost});
    }

    $new_obj->{nosuch} = $args{RetryNoSuch} || $NOSUCH;

    my $init_ref = $new_obj->{init};
    unless ( defined $$init_ref and $$init_ref ) {
        $new_obj->init();
        $$init_ref = 1;
    }

    $sess = SNMP::Session->new(
        'UseEnums' => 1,
        %sess_args, 'RetryNoSuch' => $new_obj->{nosuch}
    ) unless defined $sess;

    unless ( defined $sess ) {
        $new_obj->error_throw("SNMP::Info::new() Net-SNMP session creation failed completely.");
        return $new_obj;
    }

    if ($sess->{ErrorStr}) {
        my $sess_err = $sess->{ErrorStr} || 'no specific error';
        $new_obj->error_throw(
            "SNMP::Info::new() Net-SNMP session creation failed: $sess_err");
        return $new_obj;
    }

    $new_obj->{store}     ||= {};
    $new_obj->{sess}      = $sess;
    $new_obj->{args}      = \%args;
    $new_obj->{snmp_ver}  = $sess->{Version}   || $args{Version}   || 2;
    $new_obj->{snmp_comm} = $sess->{Community} || $args{Community} || 'public';
    $new_obj->{snmp_user} = $sess->{SecName}   || $args{SecName}   || 'initial';

    my $info = $auto_specific ? $new_obj->specify() : $new_obj;
    return $info;
}

sub device_type {
    my $info = shift;
    my $objtype = "SNMP::Info";
    my $layers = $info->layers() || '00000000';
    my $desc = $info->description() || 'undef';
    $desc =~ s/[\r\n\l]+/ /g;

    if ( $layers eq '00000000' ) {
        if ($desc ne 'undef') {
            carp("Device doesn't implement sysServices but did return sysDescr. Might give unexpected results.\n") if $info->debug();
        } else {
            return;
        }
    }

    my $id = $info->id() || 'undef';
    my $soid = $id;

    my %l3sysoidmap = (
        9     => 'SNMP::Info::Layer3::CiscoSwitch',
        11    => 'SNMP::Info::Layer2::HP',
        18    => 'SNMP::Info::Layer3::BayRS',
        42    => 'SNMP::Info::Layer3::Sun',
        43    => 'SNMP::Info::Layer2::3Com',
        45    => 'SNMP::Info::Layer2::Baystack',
        96    => 'SNMP::Info::Layer3::Whiterabbit',
        171   => 'SNMP::Info::Layer3::DLink',
        207   => 'SNMP::Info::Layer2::Allied',
        244   => 'SNMP::Info::Layer3::Lantronix',
        311   => 'SNMP::Info::Layer3::Microsoft',
        664   => 'SNMP::Info::Layer2::Adtran',
        674   => 'SNMP::Info::Layer3::Dell',
        1588  => 'SNMP::Info::Layer3::Foundry',
        1872  => 'SNMP::Info::Layer3::AlteonAD',
        1890  => 'SNMP::Info::Layer3::Redlion',
        1916  => 'SNMP::Info::Layer3::Extreme',
        1991  => 'SNMP::Info::Layer3::Foundry',
        2011  => 'SNMP::Info::Layer3::Huawei',
        2021  => 'SNMP::Info::Layer3::NetSNMP',
        2272  => 'SNMP::Info::Layer3::Passport',
        2620  => 'SNMP::Info::Layer3::CheckPoint',
        2636  => 'SNMP::Info::Layer3::Juniper',
        2925  => 'SNMP::Info::Layer1::Cyclades',
        3076  => 'SNMP::Info::Layer3::Altiga',
        3224  => 'SNMP::Info::Layer3::Netscreen',
        3375  => 'SNMP::Info::Layer3::F5',
        3417  => 'SNMP::Info::Layer3::BlueCoatSG',
        3717  => 'SNMP::Info::Layer3::Genua',
        4413  => 'SNMP::Info::Layer2::Ubiquiti',
        4526  => 'SNMP::Info::Layer2::Netgear',
        4874  => 'SNMP::Info::Layer3::ERX',
        5624  => 'SNMP::Info::Layer3::Enterasys',
        6027  => 'SNMP::Info::Layer3::Force10',
        6141  => 'SNMP::Info::Layer3::Ciena',
        6486  => 'SNMP::Info::Layer3::AlcatelLucent',
        6527  => 'SNMP::Info::Layer3::Timetra',
        6876  => 'SNMP::Info::Layer3::VMware',
        8072  => 'SNMP::Info::Layer3::NetSNMP',
        9303  => 'SNMP::Info::Layer3::PacketFront',
        10002 => 'SNMP::Info::Layer2::Ubiquiti',
        10418 => 'SNMP::Info::Layer1::Cyclades',
        11256 => 'SNMP::Info::Layer7::Stormshield',
        12325 => 'SNMP::Info::Layer3::Pf',
        12356 => 'SNMP::Info::Layer3::Fortinet',
        13191 => 'SNMP::Info::Layer3::OneAccess',
        14179 => 'SNMP::Info::Layer2::Airespace',
        14525 => 'SNMP::Info::Layer2::Trapeze',
        14823 => 'SNMP::Info::Layer3::Aruba',
        14988 => 'SNMP::Info::Layer3::Mikrotik',
        17163 => 'SNMP::Info::Layer3::Steelhead',
        17713 => 'SNMP::Info::Layer3::Cambium',
        19046 => 'SNMP::Info::Layer3::Lenovo',
        21091 => 'SNMP::Info::Layer2::Exinda',
        23867 => 'SNMP::Info::Layer3::SilverPeak',
        25461 => 'SNMP::Info::Layer3::PaloAlto',
        25506 => 'SNMP::Info::Layer3::H3C',
        26543 => 'SNMP::Info::Layer3::IBMGbTor',
        26928 => 'SNMP::Info::Layer2::Aerohive',
        28557 => 'SNMP::Info::Layer3::Hillstone',
        29671 => 'SNMP::Info::Layer3::Meraki',
        30065 => 'SNMP::Info::Layer3::Arista',
        30803 => 'SNMP::Info::Layer3::VyOS',
        35098 => 'SNMP::Info::Layer3::Pica8',
        40310 => 'SNMP::Info::Layer3::Cumulus',
        41112 => 'SNMP::Info::Layer2::Ubiquiti',
        44641 => 'SNMP::Info::Layer3::VyOS',
        46242 => 'SNMP::Info::Layer3::Netonix',
        47196 => 'SNMP::Info::Layer3::ArubaCX',
        48690 => 'SNMP::Info::Layer3::Teltonika',
    );

    my %l2sysoidmap = ();
    my %l1sysoidmap = ();
    my %l7sysoidmap = ();

    $id = $1 if ( defined($id) && $id =~ /^\.1\.3\.6\.1\.4\.1\.(\d+)/ );

    if ( $info->has_layer(3) ) {
        $objtype = 'SNMP::Info::Layer3';
        if ( defined($id) && exists $l3sysoidmap{$id} ) {
            $objtype = $l3sysoidmap{$id};
        }
    }
    elsif ( $info->has_layer(2) ) {
        $objtype = 'SNMP::Info::Layer2';
        if ( defined($id) && exists $l2sysoidmap{$id} ) {
            $objtype = $l2sysoidmap{$id};
        }
    }
    elsif ( $info->has_layer(1) ) {
        $objtype = 'SNMP::Info::Layer1';
        if ( defined($id) && exists $l1sysoidmap{$id} ) {
            $objtype = $l1sysoidmap{$id};
        }
    }
    elsif ( defined($id) && exists $l7sysoidmap{$id} ) {
        $objtype = $l7sysoidmap{$id};
    }

    return $objtype;
}

sub specify {
    my $self = shift;
    my $device_type = $self->device_type();
    unless ( defined $device_type ) {
        $self->error_throw(
            "SNMP::Info::specify() - fatal error: connect failed or missing sysServices and/or sysDescr");
        return $self;
    }
    return $self if $device_type eq 'SNMP::Info';

    eval "require $device_type;";
    if ($@) {
        croak "SNMP::Info::specify() Loading $device_type Failed. $@\n";
    }

    my $args    = $self->args();
    my $session = $self->session();
    my $sub_obj = $device_type->new(
        %$args,
        'Session'     => $session,
        'AutoSpecify' => 0
    );
    return $sub_obj || $self;
}

$INIT = 0;
$DEBUG = 0;
$BIGINT = 0;
$NOSUCH = 1;
$REPEATERS = 20;

%GLOBALS = (
    'id'           => 'sysObjectID',
    'description'  => 'sysDescr',
    'uptime'       => 'sysUpTime',
    'contact'      => 'sysContact',
    'name'         => 'sysName',
    'location'     => 'sysLocation',
    'layers'       => 'sysServices',
    'ports'        => 'ifNumber',
    'ipforwarding' => 'ipForwarding',
);

%FUNCS = (
    'interfaces' => 'ifIndex',
    'i_name'     => 'ifName',
    'i_index' => 'ifIndex',
    'i_description' => 'ifDescr',
    'i_type' => 'ifType',
    'i_mtu' => 'ifMtu',
    'i_speed' => 'ifSpeed',
    'i_mac' => 'ifPhysAddress',
    'i_up_admin' => 'ifAdminStatus',
    'i_up' => 'ifOperStatus',
    'i_lastchange' => 'ifLastChange',
    'i_alias' => 'ifAlias',
);

%MIBS = (
    'SNMPv2-MIB' => 'sysObjectID',
    'IP-MIB'     => 'ipAdEntAddr',
    'IF-MIB'     => 'ifIndex',
);

%MUNGE = (
    'mac'    => \&munge_mac,
    'i_mac'  => \&munge_mac,
    'layers' => \&munge_dec2bin,
);

sub munge_mac {
    my $mac = shift;
    return unless defined $mac;
    return unless length $mac;
    $mac = join( ':', map { sprintf "%02x", $_ } unpack( 'C*', $mac ) );
    return $mac if $mac =~ /^([0-9A-F][0-9A-F]:){5}[0-9A-F][0-9A-F]$/i;
    return;
}

sub munge_dec2bin {
    my $num = shift;
    return unless defined $num;
    $num = unpack( "B32", pack( "N", $num ) );
    $num =~ s/.*(.{8})$/$1/;
    return $num;
}

sub resolve_desthost {
    my $desthost = shift;
    $desthost =~ s/^(?:udp6:|udpv6:|udpipv6:)//x;
    my $ip = NetAddr::IP::Lite->new($desthost);
    if ($ip and $ip->bits == 32) {
        return $ip->addr;
    }
    elsif ($ip and $ip->bits == 128) {
        return 'udp6:' . $ip->addr;
    }
    croak "Unable to resolve DestHost: $desthost to an IP\n";
}

sub init {
    my $self = shift;
    local $ENV{'SNMPCONFPATH'} = '' if $self->{IgnoreNetSNMPConf};
    SNMP::initMib;
    my $mibs = $self->mibs();
    foreach my $mib ( keys %$mibs ) {
        SNMP::loadModules("$mib");
    }
    return;
}

sub args { return $_[0]->{args}; }
sub class { return $_[0]->{class}; }
sub debug { my ($self,$v)=@_; $self->{debug}=$v if defined $v; return $self->{debug}; }
sub error_throw { my ($self,$e)=@_; $self->{error}=$e if defined $e; return; }
sub error { my $self=shift; my $e=$self->{error}; $self->{error}=undef; return $e; }
sub funcs { return $_[0]->{funcs}; }
sub globals { return $_[0]->{globals}; }
sub mibs { return $_[0]->{mibs}; }
sub munge { return $_[0]->{munge}; }
sub session { my $self=shift; $self->{sess}=$_[0] if @_; return $self->{sess}; }
sub store { my $self=shift; $self->{store}=$_[0] if @_; return $self->{store}; }
sub layers { return $_[0]->_global_value('layers'); }
sub description { return $_[0]->_global_value('description'); }
sub id { return $_[0]->_global_value('id'); }
sub has_layer { my ($self,$n)=@_; my $layers=$self->layers(); return unless defined $layers; return substr($layers,8-$n,1); }

sub _global_value {
    my ($self,$attr)=@_;
    return $self->{"_$attr"} if exists $self->{"_$attr"};
    my $oid=$self->{globals}{$attr};
    return unless $oid && $self->{sess};
    my $val=$self->{sess}->get($oid);
    $self->{"_$attr"}=$val;
    return $attr eq 'layers' ? munge_dec2bin($val) : $val;
}

sub AUTOLOAD {
    my $self = shift;
    my ($sub_name) = $AUTOLOAD =~ /::([a-zA-Z0-9_-]+)$/;
    return if $sub_name eq 'DESTROY';
    my $attr=$sub_name;
    $attr =~ s/^(load|orig)_//;
    $attr =~ s/_raw$//;
    if (exists $self->{globals}{$attr}) {
        return $self->_global_value($attr);
    }
    return;
}

sub DESTROY {}

1;
