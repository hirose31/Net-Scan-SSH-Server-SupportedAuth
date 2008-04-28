# -*- mode: cperl; -*-
use Test::Base;
use Net::Scan::SSH::Server::SupportedAuth;

plan tests => 5 * blocks;

sub numeric { $_ = +($_[0] || 0); }

filters {
    map { $_ => ['numeric'] } qw(publickey_2 password_2 password_1 publickey_1)
};

run {
    my $block = shift;
    my $scanner = Net::Scan::SSH::Server::SupportedAuth->new(
        host => $block->host,
        port => $block->port,
       );

    my $result = $scanner->scan_as_hash;

    is($scanner->dump,
       $block->dump,
       $block->name . ' dump'
      );

    for my $v (2,1) {
        for my $auth (qw(publickey password)) {
            my $auth_v = "${auth}_${v}";
            is($result->{$v}->{$auth},
               $block->$auth_v,
               $block->name . " $auth_v"
              );
        }
    }
};

__END__
=== ssh2_key
--- host: localhost
--- port: 22
--- dump: {"1":{"password":0,"publickey":0},"2":{"password":0,"publickey":1}}
--- publickey_2: 1
--- password_2 : 0
--- publickey_1: 0
--- password_1 : 0

=== ssh2_pw
--- host: localhost
--- port: 62599
--- dump: {"1":{"password":0,"publickey":0},"2":{"password":1,"publickey":0}}
--- publickey_2: 0
--- password_2 : 1
--- publickey_1: 0
--- password_1 : 0

=== ssh2_both
--- host: localhost
--- port: 62598
--- dump: {"1":{"password":0,"publickey":0},"2":{"password":1,"publickey":1}}
--- publickey_2: 1
--- password_2 : 1
--- publickey_1: 0
--- password_1 : 0


=== ssh1_key
--- host: localhost
--- port: 62597
--- dump: {"1":{"password":0,"publickey":1},"2":{"password":0,"publickey":0}}
--- publickey_2: 0
--- password_2 : 0
--- publickey_1: 1
--- password_1 : 0

=== ssh1_pw
--- host: localhost
--- port: 62596
--- dump: {"1":{"password":1,"publickey":0},"2":{"password":0,"publickey":0}}
--- publickey_2: 0
--- password_2 : 0
--- publickey_1: 0
--- password_1 : 1

=== ssh1_both
--- host: localhost
--- port: 62595
--- dump: {"1":{"password":1,"publickey":1},"2":{"password":0,"publickey":0}}
--- publickey_2: 0
--- password_2 : 0
--- publickey_1: 1
--- password_1 : 1


=== ssh12_key
--- host: localhost
--- port: 62594
--- dump: {"1":{"password":0,"publickey":1},"2":{"password":0,"publickey":1}}
--- publickey_2: 1
--- password_2 : 0
--- publickey_1: 1
--- password_1 : 0

=== ssh12_pw
--- host: localhost
--- port: 62593
--- dump: {"1":{"password":1,"publickey":0},"2":{"password":1,"publickey":0}}
--- publickey_2: 0
--- password_2 : 1
--- publickey_1: 0
--- password_1 : 1

=== ssh12_both
--- host: localhost
--- port: 62592
--- dump: {"1":{"password":1,"publickey":1},"2":{"password":1,"publickey":1}}
--- publickey_2: 1
--- password_2 : 1
--- publickey_1: 1
--- password_1 : 1
