use Test::More;
use Test::MockModule;

BEGIN {
    plan tests => 10;
}

my $module = 'Form::Sec::Token';

use_ok($module);
can_ok($module, qw{new ident expire token digest match_token
                   match_digest});

{
    my $mockmodule = new Test::MockModule('Data::GUID');
    $mockmodule->mock(as_base64 => sub {'bar'} );
    my $mock2 = new Test::MockModule("Digest::SHA1");
    $mock2->mock(b64digest => sub { return 'foobar' } );
    $mock2->mock(data => sub { return } );
    
    my $token = $module->new(ident => 'foo');
    ok($token->ident() eq 'foo', 'foo identifier is stored');
    ok($token->expire() == undef, 'expire is not set');
    diag($token->token);
    ok($token->token() eq 'bar', 'the token came from Digest::GUID as_base64');
    ok($token->digest() eq 'foobar', 'the digest comes from Digest::SHA1');
}

{
    my $token = $module->new(ident => 'foo', expire => '1 day', token => 'B45K698T');
    my $token2 = $module->new(ident => 'foo', expire => '1 day', token => 'B45K698T');
    ok($token->token() eq 'B45K698T', 'Fake token got stored');
    ok($token->digest eq $token2->digest(), 'Two identical token objects have the same digest');
    ok($token->match_token('B45K698T'), 'match_token with an identical token returns true');
    ok($token->match_digest($token2->digest()), 'match_digest with an identical digest returns true');
}

