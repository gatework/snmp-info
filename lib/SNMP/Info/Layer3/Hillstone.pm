# SNMP::Info::Layer3::Hillstone
package SNMP::Info::Layer3::Hillstone;

use strict;
use warnings;
use Exporter;
use SNMP::Info::Layer3;
use SNMP::Info::Aggregate 'agg_ports_ifstack';

@SNMP::Info::Layer3::Hillstone::ISA = qw/
    SNMP::Info::Layer3
    SNMP::Info::Aggregate
    Exporter
/;
@SNMP::Info::Layer3::Hillstone::EXPORT_OK = qw//;

our ($VERSION, %GLOBALS, %FUNCS, %MIBS, %MUNGE);

$VERSION = '3.975000';

%MIBS = (
    %SNMP::Info::Layer3::MIBS,
    %SNMP::Info::Aggregate::MIBS,
    'HILLSTONE-SMI'          => 'hillstone',
    'HILLSTONE-PRODUCTS-MIB' => 'hillstoneProducts',
    'HILLSTONE-SYSTEM-MIB'   => 'sysSerialNumber',
);

%GLOBALS = (
    %SNMP::Info::Layer3::GLOBALS,
    'hillstone_serial'   => 'sysSerialNumber.0',
    'hillstone_software' => 'sysSoftware.0',
);

%FUNCS = (
    %SNMP::Info::Layer3::FUNCS,
);

%MUNGE = (
    %SNMP::Info::Layer3::MUNGE,
);

sub vendor { return 'hillstone'; }

sub model {
    my $hillstone = shift;
    my $id = $hillstone->id() || '';
    return '' unless $id;

    my $model = SNMP::translateObj($id);
    return $id unless defined $model && length $model;

    $model =~ s/^hillstone//i;
    return $model;
}

sub os { return 'stoneos'; }

sub os_ver {
    my $hillstone = shift;
    return $hillstone->hillstone_software() || '';
}

sub serial {
    my $hillstone = shift;
    return $hillstone->hillstone_serial();
}

sub agg_ports { return agg_ports_ifstack(@_) }

1;

__END__

=head1 NAME

SNMP::Info::Layer3::Hillstone - SNMP Interface to Hillstone Networks devices.

=head1 DESCRIPTION

Device abstraction for Hillstone Networks firewalls using enterprise OID 28557.
Generic interface, ARP, bridge and LLDP data are inherited from
L<SNMP::Info::Layer3>. Hillstone-specific system objects provide serial number
and software version.

=cut
