use Digest::SHA1;
use Data::GUID;

package Form::Sec::Token;

our $VERSION = '0.01';

=head1 NAME

Form::Sec::Token - protection against XSRF (Cross Site Request Forgery)

=head1 VERSION

version 0.01

=head1 SYNOPSIS

    my $FSToken = Form::Sec::Token->new(ident => $session_key,
                                        expire => 'expiration date');
    my $token = $FSToken->token();
    my $digest = $FSToken->digest();
    ## store the digest somewhere in session
    ...
    ## build your form with the expiration and token as hiden fields
    ...
    ## The form gets posted and you create a new $FSToken with the posted fields
    my $newFSToken = Form::Sec::Token->new(ident => $session_key,
                                           expire => $form_expire_field,
                                           token => $form_token_field);
    ## retrieve the digest you stored in the session
    ...
    if ($newFSToken->match_digest($digest_from_session)) {
        ## continue
    } else {
        ## ack you just intercepted an XSRF attack
    }


=cut

sub new {
    my $self = shift;
    my %opts = @_;
    my $token = $opts{token} || Data::GUID->new()->as_base64();
    return bless {ident => sub { return $opts{ident} },
                  expire => sub { $opts{expire} },
                  token => sub { $token }
                 }, $self;

}

sub ident {
    return shift->{ident}->();
}

sub expire {
    return shift->{expire}->();
}

sub token {
    return shift->{token}->();
}

sub digest {
    my $self = shift;
    return $self->_mk_digester()->( $self->token() );
}

sub match_token {
    my $self = shift;
    my $token = shift;
    return $self->_mk_digester()->( $token ) eq $self->digest();
}

sub match_digest {
    my $self = shift;
    my $digest = shift;
    return $digest eq $self->digest();

}

sub _mk_digester {
    my $self = shift;
    return sub {
        my $token = shift;
        my $sha1 = Digest::SHA1->new();
        $sha1->add(join '|', $self->ident(), $token, $self->expire);
        return $sha1->b64digest();
    }
}

1;
