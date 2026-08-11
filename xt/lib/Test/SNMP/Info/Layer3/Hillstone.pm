package Test::SNMP::Info::Layer3::Hillstone;

use Test::Class::Most parent => 'My::Test::Class';
use SNMP::Info::Layer3::Hillstone;

sub startup : Tests(startup => 1) {
    my $test = shift;
    $test->SUPER::startup();
    $test->todo_methods(1);
}

sub setup : Tests(setup) {
    my $test = shift;
    $test->SUPER::setup;

    my $cache_data = {
        '_layers' => 78,
        '_description' => 'Hillstone Networks firewall',
        # HILLSTONE-PRODUCTS-MIB::SG-6000-X5100
        '_id' => '.1.3.6.1.4.1.28557.1.21',
        '_hillstone_serial' => 'HS1234567890',
        '_hillstone_software' => 'StoneOS 5.5R10',
    };
    $test->{info}->cache($cache_data);
}

sub vendor : Tests(2) {
    my $test = shift;
    can_ok($test->{info}, 'vendor');
    is($test->{info}->vendor(), 'hillstone', q(Vendor returns 'hillstone'));
}

sub model : Tests(2) {
    my $test = shift;
    can_ok($test->{info}, 'model');
    like($test->{info}->model(), qr/(?:SG-6000-X5100|1\.3\.6\.1\.4\.1\.28557\.1\.21)/,
        'Model is translated when product MIB is loaded');
}

sub os : Tests(2) {
    my $test = shift;
    can_ok($test->{info}, 'os');
    is($test->{info}->os(), 'stoneos', q(os returns 'stoneos'));
}

sub os_ver : Tests(2) {
    my $test = shift;
    can_ok($test->{info}, 'os_ver');
    is($test->{info}->os_ver(), 'StoneOS 5.5R10', 'software version is returned');
}

sub serial : Tests(2) {
    my $test = shift;
    can_ok($test->{info}, 'serial');
    is($test->{info}->serial(), 'HS1234567890', 'serial number is returned');
}

1;
