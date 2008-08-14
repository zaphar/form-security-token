use Test::More;
use Test::MockModule;

BEGIN {
    plan tests => 11;
}

my $module = 'Form::Security::Token';

use_ok($module);
can_ok($module, qw{new ident expire token digest ts 
                   assert_eq_digest
                   assert_valid_digest
                   form_fields});

{
    my $mockmodule = new Test::MockModule('Data::GUID');
    $mockmodule->mock(as_base64 => sub {'bar'} );
    my $mock2 = new Test::MockModule("Digest::SHA1");
    $mock2->mock(b64digest => sub { return 'foobar' } );
    $mock2->mock(data => sub { return } );
    
    my $token = $module->new(ident => 'foo');
    ok($token->ident() eq 'foo', 'foo identifier is stored');
    ok($token->expire() == undef, 'expire is not set');
    ok($token->token() eq 'bar', 'the token came from Digest::GUID as_base64');
    ok($token->digest() eq 'foobar', 'the digest comes from Digest::SHA1');
}

{
    my $token = $module->new(ident => 'foo', expire => '30', token => 'B45K698T');
    my $token2 = $module->new(ident => 'foo', expire => '30', token => 'B45K698T');
    ok($token->token() eq 'B45K698T', 'Fake token got stored');
    ok($token->digest eq $token2->digest(), 'Two identical token objects have the same digest');
    ok($token->assert_eq_digest($token2->digest()), 'assert_eq_digest with an identical digest returns true');
    #diag($token->form_fields());
    ok($token->form_fields() eq "<input type='hidden' name='expire' id='expire' value='30' />".
                                "<input type='hidden' name='token' id='token' value='B45K698T' />".
                                "<input type='hidden' name='ts' id='ts' value='".$token->ts."' />",
       'form_fields returns a string with hidden form_fields');
    #diag($token->form_fields('baz'));
    ok($token->form_fields('baz') eq "<input type='hidden' name='bazexpire' id='bazexpire' value='30' />".
                                "<input type='hidden' name='baztoken' id='baztoken' value='B45K698T' />".
                                "<input type='hidden' name='bazts' id='bazts' value='".$token->ts."' />",
       'hidden form_fields use a prefix if specified');
    my $token3 = $module->new(ident => 'foo');
    my $token4 = $module->new(ident => 'foo', ts => $token3->ts, 
                              token => $token3->token());
    #diag("token3 - Digest:". $token3->digest 
    #     ." ts: ".$token3->ts 
    #     . " Token: ". $token3->token()
    #     . " Ident: ". $token3->ident()
    #     . " Expire: ". $token3->expire()
    #    );
    #diag("token4 - Digest:". $token4->digest ." ts: ".$token4->ts 
    #     . " Token: ". $token4->token()
    #     . " Ident: ". $token4->ident()
    #     . " Expire: ". $token4->expire()
    #    );
    
    ok($token3->assert_valid_digest($token4->digest),
        'assert_valid_digest with same token and no expiration asserts true');
    
    $token3 = $module->new(ident => 'foo',
                           expire => '30');
    $token4 = $module->new(ident => 'foo', 
                           ts => $token3->ts,
                           expire => '30',
                           token => $token3->token());
    #diag("token3 - Digest:". $token3->digest 
    #     ." ts: ".$token3->ts 
    #     . " Token: ". $token3->token()
    #     . " Ident: ". $token3->ident()
    #     . " Expire: ". $token3->expire()
    #    );
    #diag("token4 - Digest:". $token4->digest ." ts: ".$token4->ts 
    #     . " Token: ". $token4->token()
    #     . " Ident: ". $token4->ident()
    #     . " Expire: ". $token4->expire()
    #    );
    
    ok($token3->assert_valid_digest($token4->digest),
        'assert_valid_digest with same token and unexpired asserts true');
    $token3 = $module->new(ident => 'foo',
                           expire => -1);
    $token4 = $module->new(ident => 'foo', 
                           ts => $token3->ts,
                           expire => -1,
                           token => $token3->token());
    ok(!$token3->assert_valid_digest($token4->digest),
        'assert_valid_digest with same token but expired asserts false');
}

