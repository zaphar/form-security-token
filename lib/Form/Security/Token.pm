package Form::Security::Token;

use Digest::SHA1;
use Data::GUID;
use DateTime;

our $VERSION = '0.01';

=head1 NAME

Form::Security::Token - protection against XSRF (Cross Site Request Forgery)

=head1 VERSION

version 0.01

=head1 SYNOPSIS

    my $FSToken = Form::Security::Token->new(ident => $session_key,
                                        expire => 'time to live in minutes');
    my $token = $FSToken->token();
    my $digest = $FSToken->digest();
    ## store the digest somewhere in session
    ...
    ## build your form with the expiration and token as hiden fields
    $form .= $FSToken->form_fields('XSRF_') . '</form>';
    ...
    ## The form gets posted and you create a new $FSToken with the posted fields
    my $newFSToken = Form::Security::Token->new(ident => $session_key,
                                           expire => $form_expire_field,
                                           ts     => $form_ts_field;
                                           token => $form_token_field);
    ## retrieve the digest you stored in the session
    ...
    if ($newFSToken->assert_valid_digest($digest_from_session)) {
        ## continue
    } else {
        ## ack you just intercepted an XSRF attack
        ## maybe you should log it?
    }


=head1 CONSTRUCTORS
 
=head2 new

object constructor. requires an ident => $identifier pair in the args.
Optionally can have expire => 'minutes to live' pair also in the args
Also Optionally can have token => $token specified in args.

=cut

sub new {
    my $self = shift;
    my %opts = @_;
    my $token = $opts{token} || Data::GUID->new()->as_base64();
    my $ts = $opts{ts} || DateTime->now()->epoch();
    return bless {ident => sub { return $opts{ident} },
                  expire => sub { $opts{expire} },
                  ts     => sub { $ts },
                  token => sub { $token }
                 }, $self;

}

=head1 ATTRIBUTES

=head2 ident

Immutable: returns the identifier attribute

=cut

sub ident {
    return shift->{ident}->();
}

=head2 expire 

Immutable: returns the expire attribute

=cut

sub expire {
    return shift->{expire}->();
}

=head2 token

Immutable: returns the token attribute

=cut

sub token {
    return shift->{token}->();
}

=head2 t

Immutable: returns the timestamp as a unix epoch

=cut

sub ts {
    return shift->{ts}->();
}
=head1 METHODS

=head2 digest

returns the digest of the stored data

=cut

sub digest {
    my $self = shift;
    return $self->_mk_digester()->( $self->token() );
}

=head2 assert_eq_digest

takes a digest as an argument and compares it to its own digest. 
Returns true or false

=cut

sub assert_eq_digest {
    my $self = shift;
    my $digest = shift;
    return $digest eq $self->digest();

}

=head2 assert_valid_digest

takes a digest as an argument and returns true if valid false if not
also takes expiration into account

=cut

sub assert_valid_digest {
    my $self = shift;
    my $digest = shift;
    my $eq = $digest eq $self->digest();
    my $st = DateTime->from_epoch(epoch => $self->ts());
    return if !$eq;
    # is there a token expiration?
    return 1 if $eq and !$self->expire;
    my $now = DateTime->now();
    my $expiration = $st->add(minutes => $self->expire);
    warn "now: $now";
    warn "expiration: $expiration";
    if ($now < $expiration) {
        return 1;
    }
    return;
}

=head2 form_fields

takes an optional $prefix argument
outputs the hidden form fields to include in your html form
prefixing the field names with the prefix if specified

=cut

sub form_fields {
    my $self = shift;
    my $prefix = shift;
    my $string = "<input type='hidden' name='$prefix"."expire' id='$prefix"."expire' value='".$self->expire()."' />";
    $string .= "<input type='hidden' name='$prefix"."token' id='$prefix"."token' value='".$self->token()."' />";
    $string .= "<input type='hidden' name='$prefix"."ts' id='$prefix"."ts' value='".$self->ts()."' />";
    return $string;
}

sub _mk_digester {
    my $self = shift;
    return sub {
        my $token = shift;
        my $sha1 = Digest::SHA1->new();
        $sha1->add(join '|', $self->ident(), $token, $self->expire, $self->ts);
        return $sha1->b64digest();
    }
}

=head1 AUTHOR

Jeremy Wall <jwall@google.com>

=head1 LICENSE

This library is free software, you can redistribute it and/or modify it
under the same terms as Perl itself.


=cut

1;
